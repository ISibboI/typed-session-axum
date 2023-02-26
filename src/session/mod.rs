// Much of this code is lifted directly from
// `tide::sessions::middleware::SessionMiddleware`. See: https://github.com/http-rs/tide/blob/20fe435a9544c10f64245e883847fc3cd1d50538/src/sessions/middleware.rs

use std::fmt::Debug;
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    http::{
        header::{HeaderValue, COOKIE, SET_COOKIE},
        Request, StatusCode,
    },
    response::Response,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use futures::future::BoxFuture;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tower::{Layer, Service};
use typed_session::{
    SessionCookieCommand, SessionExpiry, SessionRenewalStrategy, SessionStore,
    SessionStoreConnector,
};

/// A type alias which provides a handle to the underlying session.
///
/// This is provided via [`http::Extensions`](http::Extensions). Most
/// applications will use the
/// [`ReadableSession`](crate::extractors::ReadableSession) and
/// [`WritableSession`](crate::extractors::WritableSession) extractors rather
/// than using the handle directly. A notable exception is when using this
/// library as a generic Tower middleware: such use cases will consume the
/// handle directly.
pub type SessionHandle<SessionData> = Arc<RwLock<typed_session::Session<SessionData>>>;

/// Layer that provides cookie-based sessions.
#[derive(Debug)]
pub struct SessionLayer<SessionData, SessionStoreConnection> {
    store: SessionStore<SessionData, SessionStoreConnection, 64>,
    cookie_path: String,
    cookie_name: String,
    cookie_domain: Option<String>,
    session_ttl: Option<Duration>,
    min_session_renew_time: Option<Duration>,
    same_site_policy: SameSite,
    secure: bool,
}

impl<SessionData, SessionStoreConnection: Clone> Clone
    for SessionLayer<SessionData, SessionStoreConnection>
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            cookie_path: self.cookie_path.clone(),
            cookie_name: self.cookie_name.clone(),
            cookie_domain: self.cookie_domain.clone(),
            session_ttl: self.session_ttl,
            min_session_renew_time: self.min_session_renew_time,
            same_site_policy: self.same_site_policy,
            secure: self.secure,
        }
    }
}

impl<SessionData, SessionStoreConnection: SessionStoreConnector<SessionData>>
    SessionLayer<SessionData, SessionStoreConnection>
{
    /// Creates a layer which will attach a [`SessionHandle`] to requests via an
    /// extension. This session is derived from a cryptographically signed
    /// cookie. When the client sends a valid, known cookie then the session is
    /// hydrated from this. Otherwise a new cookie is created and returned in
    /// the response.
    ///
    /// The default behaviour is to enable "guest" sessions with
    /// [`PersistencePolicy::Always`].
    ///
    /// # Panics
    ///
    /// `SessionLayer::new` will panic if the secret is less than 64 bytes.
    ///
    /// # Customization
    ///
    /// The configuration of the session may be adjusted according to the needs
    /// of your application:
    ///
    /// ```rust
    /// # use typed_session_axum::{SessionLayer, typed_session::MemoryStore};
    /// # use std::time::Duration;
    /// # use axum_extra::extract::cookie::SameSite;
    /// SessionLayer::new(
    ///     MemoryStore::<(), _>::new(),
    /// )
    /// .with_cookie_name("your.cookie.name")
    /// .with_cookie_path("/some/path")
    /// .with_cookie_domain("www.example.com")
    /// .with_same_site_policy(SameSite::Strict)
    /// .with_session_ttl(Some(Duration::from_secs(60 * 5)))
    /// .with_min_session_renew_time(Some(Duration::from_secs(60 * 5)))
    /// .with_secure(true);
    /// ```
    pub fn new(store: SessionStoreConnection) -> Self {
        Self {
            store: SessionStore::new(
                store,
                SessionRenewalStrategy::AutomaticRenewal {
                    time_to_live: chrono::Duration::seconds(24 * 60 * 60),
                    maximum_remaining_time_to_live_for_renewal: chrono::Duration::seconds(
                        20 * 60 * 60,
                    ),
                },
            ),
            cookie_path: "/".into(),
            cookie_name: "id".into(),
            cookie_domain: None,
            same_site_policy: SameSite::Strict,
            session_ttl: Some(Duration::from_secs(24 * 60 * 60)),
            min_session_renew_time: None,
            secure: true,
        }
    }

    /// Sets a cookie path for the session. Defaults to `"/"`.
    pub fn with_cookie_path(mut self, cookie_path: impl AsRef<str>) -> Self {
        self.cookie_path = cookie_path.as_ref().to_owned();
        self
    }

    /// Sets a cookie name for the session. Defaults to `"axum.sid"`.
    pub fn with_cookie_name(mut self, cookie_name: impl AsRef<str>) -> Self {
        self.cookie_name = cookie_name.as_ref().to_owned();
        self
    }

    /// Sets a cookie domain for the session. Defaults to `None`.
    pub fn with_cookie_domain(mut self, cookie_domain: impl AsRef<str>) -> Self {
        self.cookie_domain = Some(cookie_domain.as_ref().to_owned());
        self
    }

    /// Sets a cookie same site policy for the session. Defaults to
    /// `SameSite::Strict`.
    pub fn with_same_site_policy(mut self, policy: SameSite) -> Self {
        self.same_site_policy = policy;
        self
    }

    /// Sets a cookie time-to-live (ttl) for the session. Defaults to
    /// `Duration::from_secs(60 * 60 24)`; one day.
    pub fn with_session_ttl(mut self, session_ttl: Option<Duration>) -> Self {
        self.session_ttl = session_ttl;
        self
    }

    /// Sets the minimum time to wait between renewing the session.
    /// Renewing means changing the session key, and in turn updating the ttl.
    /// Defaults to `None`.
    pub fn with_min_session_renew_time(mut self, min_session_renew_time: Option<Duration>) -> Self {
        self.min_session_renew_time = min_session_renew_time;
        self
    }

    /// Sets a cookie secure attribute for the session. Defaults to `true`.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    fn build_cookie(&self, cookie_value: String) -> Cookie<'static> {
        let mut cookie = Cookie::build(self.cookie_name.clone(), cookie_value)
            .http_only(true)
            .same_site(self.same_site_policy)
            .secure(self.secure)
            .path(self.cookie_path.clone())
            .finish();

        if let Some(ttl) = self.session_ttl {
            cookie.set_expires(Some((std::time::SystemTime::now() + ttl).into()));
        }

        if let Some(cookie_domain) = self.cookie_domain.clone() {
            cookie.set_domain(cookie_domain)
        }

        cookie
    }

    fn build_removal_cookie(&self) -> Cookie<'static> {
        let cookie = Cookie::build(self.cookie_name.clone(), "")
            .http_only(true)
            .path(self.cookie_path.clone());

        let mut cookie = if let Some(cookie_domain) = self.cookie_domain.clone() {
            cookie.domain(cookie_domain)
        } else {
            cookie
        }
        .finish();

        cookie.make_removal();

        cookie
    }
}

async fn load_or_create<
    SessionData: Default + Debug,
    SessionStoreConnection: SessionStoreConnector<SessionData>,
    const COOKIE_LENGTH: usize,
>(
    store: &SessionStore<SessionData, SessionStoreConnection, COOKIE_LENGTH>,
    cookie_value: Option<impl AsRef<str>>,
) -> SessionHandle<SessionData> {
    let session = match cookie_value {
        Some(cookie_value) => store.load_session(cookie_value).await.ok().flatten(),
        None => None,
    };

    Arc::new(RwLock::new(session.unwrap_or_default()))
}

impl<
        Inner,
        SessionData: Clone,
        SessionStoreConnection: SessionStoreConnector<SessionData> + Clone,
    > Layer<Inner> for SessionLayer<SessionData, SessionStoreConnection>
{
    type Service = Session<Inner, SessionData, SessionStoreConnection>;

    fn layer(&self, inner: Inner) -> Self::Service {
        Session {
            inner,
            layer: Arc::new(self.clone()),
        }
    }
}

/// Session service container.
#[derive(Debug)]
pub struct Session<Inner, SessionData, SessionStoreConnection> {
    inner: Inner,
    layer: Arc<SessionLayer<SessionData, SessionStoreConnection>>,
}

impl<
        Inner,
        ReqBody,
        ResBody,
        SessionData: Clone + Default + Debug + Send + Sync + 'static,
        SessionStoreConnection: SessionStoreConnector<SessionData> + 'static,
    > Service<Request<ReqBody>> for Session<Inner, SessionData, SessionStoreConnection>
where
    Inner: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    ResBody: Send + 'static,
    ReqBody: Send + 'static,
    Inner::Future: Send + 'static,
{
    type Response = Inner::Response;
    type Error = Inner::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let session_layer = self.layer.clone();

        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            let now = Utc::now();

            // Multiple cookies may be all concatenated into a single Cookie header
            // separated with semicolons (HTTP/1.1 behaviour) or into multiple separate
            // Cookie headers (HTTP/2 behaviour). Search for the session cookie from
            // all Cookie headers, assuming both forms are possible.
            let cookie_value = request
                .headers()
                .get_all(COOKIE)
                .iter()
                .filter_map(|cookie_header| cookie_header.to_str().ok())
                .flat_map(|cookie_header| cookie_header.split(';'))
                .filter_map(|cookie_header| Cookie::parse_encoded(cookie_header.trim()).ok())
                .filter(|cookie| cookie.name() == session_layer.cookie_name)
                .map(|cookie| cookie.value().to_owned())
                .next();

            let session_handle = load_or_create(&session_layer.store, cookie_value).await;

            // TODO update session expiry only after min update time
            let mut session = session_handle.write().await;
            if let Some(ttl) = session_layer.session_ttl {
                (*session).expire_in(now, ttl);
            }
            drop(session);

            request.extensions_mut().insert(session_handle.clone());
            let mut response = inner.call(request).await?;

            let session = RwLock::into_inner(
                Arc::try_unwrap(session_handle).expect("Session handle still has owners."),
            );

            let store = &session_layer.store;
            match store.store_session(session).await {
                Ok(SessionCookieCommand::DoNothing) => {}
                Ok(SessionCookieCommand::Set {
                    cookie_value,
                    expiry,
                }) => {
                    let mut cookie = session_layer.build_cookie(cookie_value);
                    if let SessionExpiry::DateTime(expiry) = expiry {
                        cookie.set_expires(Some(
                            OffsetDateTime::from_unix_timestamp(expiry.timestamp()).unwrap(),
                        ));
                    }

                    response.headers_mut().append(
                        SET_COOKIE,
                        HeaderValue::from_str(&cookie.to_string()).unwrap(),
                    );
                }
                Ok(SessionCookieCommand::Delete) => {
                    let removal_cookie = session_layer.build_removal_cookie();

                    response.headers_mut().append(
                        SET_COOKIE,
                        HeaderValue::from_str(&removal_cookie.to_string()).unwrap(),
                    );
                }
                Err(error) => {
                    tracing::error!("Failed to store session: {error:?}");
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                }
            }

            Ok(response)
        })
    }
}

impl<Inner: Clone, SessionData, SessionStoreConnection: Clone> Clone
    for Session<Inner, SessionData, SessionStoreConnection>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{Request, Response};
    use axum_extra::extract::cookie::Cookie;
    use http::{
        header::{COOKIE, SET_COOKIE},
        HeaderValue, StatusCode,
    };
    use hyper::Body;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;
    use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

    use crate::{typed_session::MemoryStore, SessionHandle, SessionLayer};

    #[derive(Deserialize, Serialize, PartialEq, Debug)]
    struct Counter {
        counter: i32,
    }

    enum ExpectedResult {
        Some,
        None,
    }

    #[tokio::test]
    async fn sets_session_cookie() {
        let store = MemoryStore::<(), _>::new();
        let session_layer = SessionLayer::new(store);
        let mut service = ServiceBuilder::new().layer(session_layer).service_fn(echo);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        assert!(res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("axum.sid="))
    }

    #[tokio::test]
    async fn uses_valid_session() {
        let store = MemoryStore::<(), _>::new();
        let session_layer = SessionLayer::new(store);
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 0 });

        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.to_owned());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 1 });
    }

    #[tokio::test]
    async fn multiple_cookies_in_single_header() {
        let store = MemoryStore::<(), _>::new();
        let session_layer = SessionLayer::new(store);
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        // build a Cookie header that contains two cookies: an unrelated dummy cookie,
        // and the given session cookie
        let request_cookie =
            HeaderValue::from_str(&format!("key=value; {}", session_cookie.to_str().unwrap()))
                .unwrap();

        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 0 });

        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request.headers_mut().insert(COOKIE, request_cookie);
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 1 });
    }

    #[tokio::test]
    async fn multiple_cookie_headers() {
        let store = MemoryStore::<(), _>::new();
        let session_layer = SessionLayer::new(store);
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();
        let dummy_cookie = HeaderValue::from_str("key=value").unwrap();

        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 0 });

        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request.headers_mut().append(COOKIE, dummy_cookie);
        request.headers_mut().append(COOKIE, session_cookie);
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 1 });
    }

    #[tokio::test]
    async fn no_cookie_stored_when_no_session_is_required() {
        let store = MemoryStore::<(), _>::new();
        let session_layer = SessionLayer::new(store);
        let mut service = ServiceBuilder::new().layer(session_layer).service_fn(echo);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        assert!(res.headers().get(SET_COOKIE).is_none());
    }

    async fn invalid_session_check_cookie_result(
        change_data: bool,
        expect_cookie_header: (ExpectedResult, ExpectedResult),
    ) {
        let (expect_cookie_header_first, expect_cookie_header_second) = expect_cookie_header;
        let store = MemoryStore::<(), _>::new_with_logger();
        let session_layer = SessionLayer::new(store);
        let mut service = ServiceBuilder::new()
            .layer(&session_layer)
            .service_fn(echo_read_session);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        match expect_cookie_header_first {
            ExpectedResult::Some => assert!(
                res.headers().get(SET_COOKIE).is_some(),
                "Set-Cookie must be present for first response"
            ),
            ExpectedResult::None => assert!(
                res.headers().get(SET_COOKIE).is_none(),
                "Set-Cookie must not be present for first response"
            ),
        }

        let mut service =
            ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(move |req| async move {
                    if change_data {
                        echo_with_session_change(req).await
                    } else {
                        echo_read_session(req).await
                    }
                });
        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, "axum.sid=aW52YWxpZC1zZXNzaW9uLWlk".parse().unwrap());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        match expect_cookie_header_second {
            ExpectedResult::Some => assert!(
                res.headers().get(SET_COOKIE).is_some(),
                "Set-Cookie must be present for second response"
            ),
            ExpectedResult::None => assert!(
                res.headers().get(SET_COOKIE).is_none(),
                "Set-Cookie must not be present for second response"
            ),
        }
    }

    #[tokio::test]
    async fn invalid_session_always_sets_guest_cookie() {
        invalid_session_check_cookie_result(false, (ExpectedResult::Some, ExpectedResult::Some))
            .await;
    }

    #[tokio::test]
    async fn invalid_session_sets_new_session_cookie_when_data_changes() {
        invalid_session_check_cookie_result(true, (ExpectedResult::None, ExpectedResult::Some))
            .await;
    }

    #[tokio::test]
    async fn invalid_session_sets_no_cookie_when_no_data_changes() {
        invalid_session_check_cookie_result(false, (ExpectedResult::None, ExpectedResult::None))
            .await;
    }

    #[tokio::test]
    async fn invalid_session_changed_only_sets_cookie_when_changed() {
        invalid_session_check_cookie_result(true, (ExpectedResult::None, ExpectedResult::Some))
            .await;
    }

    #[tokio::test]
    async fn destroyed_sessions_sets_removal_cookie() {
        let store = MemoryStore::<(), _>::new();
        let session_layer = SessionLayer::new(store);
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(destroy);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let session_cookie = res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let mut request = Request::get("/destroy").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.parse().unwrap());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(
            Cookie::from_str(res.headers().get(SET_COOKIE).unwrap().to_str().unwrap())
                .unwrap()
                .value(),
            ""
        );
    }

    async fn echo(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(req.into_body()))
    }

    async fn echo_read_session(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        {
            let session_handle = req.extensions().get::<SessionHandle<()>>().unwrap();
            let session = session_handle.write().await;
            let _ = session.data();
        }
        Ok(Response::new(req.into_body()))
    }

    async fn echo_with_session_change(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        {
            let session_handle = req.extensions().get::<SessionHandle<()>>().unwrap();
            let mut session = session_handle.write().await;
            session.data_mut();
        }
        Ok(Response::new(req.into_body()))
    }

    async fn destroy(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        // Destroy the session if we received a session cookie.
        if req.headers().get(COOKIE).is_some() {
            let session_handle = req.extensions().get::<SessionHandle<()>>().unwrap();
            let mut session = session_handle.write().await;
            session.delete();
        }

        Ok(Response::new(req.into_body()))
    }

    async fn increment(mut req: Request<Body>) -> Result<Response<Body>, BoxError> {
        let counter;

        {
            let session_handle = req.extensions().get::<SessionHandle<i32>>().unwrap();
            let mut session = session_handle.write().await;
            *session.data_mut() += 1;
            counter = *session.data();
        }

        let body = serde_json::to_string(&Counter { counter }).unwrap();
        *req.body_mut() = Body::from(body);

        Ok(Response::new(req.into_body()))
    }
}
