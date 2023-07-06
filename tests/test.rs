use axum::error_handling::HandleErrorLayer;
use axum::routing::get;
use axum::{Extension, Router};
use axum_extra::extract::cookie::Cookie;
use http::header::{COOKIE, SET_COOKIE};
use http::{HeaderValue, Request, StatusCode};
use hyper::service::Service;
use hyper::Body;
use std::convert::Infallible;
use tower::{ServiceBuilder, ServiceExt};
use typed_session::{MemoryStore, NoLogger};
use typed_session_axum::{ReadableSession, SessionLayer, SessionLayerError, WritableSession};

fn app() -> Router {
    async fn handle_session_layer_error<SessionStoreConnectorError, InnerError>(
        _: SessionLayerError<SessionStoreConnectorError, InnerError>,
    ) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    Router::new()
        .route("/hello-world", get(|| async { "Hello, World!" }))
        .route(
            "/get",
            get(|session: ReadableSession<bool>| async move { format!("{}", session.data()) }),
        )
        .route(
            "/set",
            get(|mut session: WritableSession<bool>| async move {
                *session.data_mut() = true;
            }),
        )
        .route(
            "/unset",
            get(|mut session: WritableSession<bool>| async move {
                *session.data_mut() = false;
            }),
        )
        .route(
            "/delete",
            get(|mut session: WritableSession<bool>| async move {
                session.delete();
            }),
        )
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(
                    handle_session_layer_error::<Infallible, Infallible>,
                ))
                .layer(SessionLayer::<bool, MemoryStore<bool, NoLogger>>::new()),
        )
        .layer(Extension(MemoryStore::<bool, _>::new()))
}

#[tokio::test]
async fn test_hello_world() {
    let app = app();

    // `Router` implements `tower::Service<Request<Body>>` so we can
    // call it like any tower service, no need to run an HTTP server.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/hello-world")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"Hello, World!");
}

#[tokio::test]
async fn test_persistent_session() {
    let mut app = app();

    // Calling delete without a cookie should work, and simply return no cookie.
    let response = app
        .call(
            Request::builder()
                .uri("/delete")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(SET_COOKIE));

    // Calling get without a cookie should return the default value, and return no cookie.
    let response = app
        .call(Request::builder().uri("/get").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(SET_COOKIE));
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"false");

    // Calling set should return a new cookie associated with the value true.
    let response = app
        .call(Request::builder().uri("/set").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(SET_COOKIE));
    let cookie = response.headers().get(SET_COOKIE).unwrap().clone();
    let cookie = Cookie::parse_encoded(cookie.to_str().unwrap()).unwrap();
    println!("{cookie:?}");
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"");

    // Calling get without cookie should return the default value.
    let response = app
        .call(Request::builder().uri("/get").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(SET_COOKIE));
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"false");

    // Calling get with the previous cookie should remember the value.
    let response = app
        .call(
            Request::builder()
                .uri("/get")
                .header(COOKIE, HeaderValue::from_str(&cookie.to_string()).unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(SET_COOKIE));
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"true");

    // Calling unset should return a new cookie associated with the value false.
    let response = app
        .call(
            Request::builder()
                .uri("/unset")
                .header(COOKIE, HeaderValue::from_str(&cookie.to_string()).unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(SET_COOKIE));
    let cookie2 = response.headers().get(SET_COOKIE).unwrap().clone();
    let cookie2 = Cookie::parse_encoded(cookie2.to_str().unwrap()).unwrap();
    println!("{cookie2:?}");
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"");

    // Calling get with the old cookie should return the default value false.
    let response = app
        .call(
            Request::builder()
                .uri("/get")
                .header(COOKIE, HeaderValue::from_str(&cookie.to_string()).unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(SET_COOKIE));
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"false");

    // Calling get with the new cookie should return the previously set value false.
    let response = app
        .call(
            Request::builder()
                .uri("/get")
                .header(COOKIE, HeaderValue::from_str(&cookie2.to_string()).unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(SET_COOKIE));
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"false");

    // Calling set with the first cookie should return a new cookie associated with the value true.
    // The fact that we pass an illegal cookie should not disturb.
    let response = app
        .call(
            Request::builder()
                .uri("/set")
                .header(COOKIE, HeaderValue::from_str(&cookie.to_string()).unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(SET_COOKIE));
    let cookie3 = response.headers().get(SET_COOKIE).unwrap().clone();
    let cookie3 = Cookie::parse_encoded(cookie3.to_str().unwrap()).unwrap();
    println!("{cookie3:?}");
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"");

    // Calling get with the newest cookie should return the previously set value true.
    // This should not be disturbed by the fact that the value was set while passing an illegal cookie.
    let response = app
        .call(
            Request::builder()
                .uri("/get")
                .header(COOKIE, HeaderValue::from_str(&cookie3.to_string()).unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(SET_COOKIE));
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&body[..], b"true");
}
