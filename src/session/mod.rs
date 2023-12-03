// Much of this code is lifted directly from
// `tide::sessions::middleware::SessionMiddleware`. See: https://github.com/http-rs/tide/blob/20fe435a9544c10f64245e883847fc3cd1d50538/src/sessions/middleware.rs

use std::fmt::{Debug, Display, Formatter};
use std::{
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    http::{
        header::{HeaderValue, COOKIE, SET_COOKIE},
        Request, StatusCode,
    },
    response::Response,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use futures::future::BoxFuture;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tower::{Layer, Service, ServiceExt};
use typed_session::{
    SessionCookieCommand, SessionExpiry, SessionRenewalStrategy, SessionStore,
    SessionStoreConnector,
};

/// A type alias which provides a handle to the underlying session.
///
/// This is provided via [`http::Extensions`](axum::http::Extensions).
/// Most applications will use the
/// [`ReadableSession`](crate::extractors::ReadableSession) and
/// [`WritableSession`](crate::extractors::WritableSession) extractors rather
/// than using the handle directly. A notable exception is when using this
/// library as a generic Tower middleware: such use cases will consume the
/// handle directly.
pub type SessionHandle<SessionData> = Arc<RwLock<typed_session::Session<SessionData>>>;

/// Layer that provides cookie-based sessions.
/// See [`SessionLayer::new`] for more details.
#[derive(Debug)]
pub struct SessionLayer<SessionData, SessionStoreConnection> {
    store: SessionStore<SessionData, SessionStoreConnection>,
    cookie_path: String,
    cookie_name: String,
    cookie_domain: Option<String>,
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
            same_site_policy: self.same_site_policy,
            secure: self.secure,
        }
    }
}

impl<SessionData, SessionStoreConnection: SessionStoreConnector<SessionData>> Default
    for SessionLayer<SessionData, SessionStoreConnection>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<SessionData, SessionStoreConnection: SessionStoreConnector<SessionData>>
    SessionLayer<SessionData, SessionStoreConnection>
{
    /// Creates a layer which will attach a [`SessionHandle`] to requests via an
    /// extension. This session is derived from a cookie. When the client sends
    /// a valid, known cookie then the session is loaded using the cookie as key.
    /// Otherwise, the `SessionHandle` will contain a default session which is
    /// only persisted if it was mutably accessed.
    ///
    /// The layer expects the `SessionStoreConnection` to exist as an extension.
    /// It is a type that implements [`SessionStoreConnector`] with the correct
    /// `SessionData`.
    /// The type is required to implement `Send`, `Sync` and `Clone`, such that
    /// the session layer can make its own copy (required due to some details of
    /// axum, specifically the extensions do not get automatically attached to a
    /// response from the corresponding request).
    ///
    /// The `SessionStoreConnection` can e.g. be a type representing a simple
    /// database connection, a connection pool or database transaction. Since
    /// sessions cannot be updated concurrently, using transactions may be useful,
    /// to be able to roll back all changes in case the session got updated.
    /// It is important that the `SessionStoreConnection` in the extension is
    /// ready, because `axum` does not use backpressure, but explicit readiness
    /// checks.
    ///
    /// # Customization
    ///
    /// The configuration of the session may be adjusted according to the needs
    /// of your application:
    ///
    /// ```rust
    /// # use typed_session_axum::{SessionLayer, typed_session::MemoryStore};
    /// # use chrono::Duration;
    /// # use axum_extra::extract::cookie::SameSite;
    /// # use typed_session::NoLogger;
    /// use typed_session::SessionRenewalStrategy;
    /// SessionLayer::<i32, MemoryStore<i32, NoLogger>>::new()
    /// .with_cookie_name("id") // for security reasons, just stick with the default "id" here
    /// .with_cookie_path("/some/path")
    /// .with_cookie_domain("www.example.com")
    /// .with_same_site_policy(SameSite::Strict)
    /// .with_session_renewal_strategy(SessionRenewalStrategy::AutomaticRenewal {
    ///     time_to_live: Duration::hours(24),
    ///     maximum_remaining_time_to_live_for_renewal: Duration::hours(20),
    /// })
    /// .with_secure(true);
    /// ```
    pub fn new() -> Self {
        Self {
            store: SessionStore::new(SessionRenewalStrategy::AutomaticRenewal {
                time_to_live: chrono::Duration::seconds(24 * 60 * 60),
                maximum_remaining_time_to_live_for_renewal: chrono::Duration::seconds(20 * 60 * 60),
            }),
            cookie_path: "/".into(),
            cookie_name: "id".into(),
            cookie_domain: None,
            same_site_policy: SameSite::Strict,
            secure: true,
        }
    }

    /// Sets the url path for which the session cookie is valid. Defaults to `"/"`.
    pub fn with_cookie_path(mut self, cookie_path: impl AsRef<str>) -> Self {
        self.cookie_path = cookie_path.as_ref().to_owned();
        self
    }

    /// Sets the name of the session cookie. Defaults to `"id"`.
    /// For security reasons, choose a generic name, and ideally just stick with the default.
    pub fn with_cookie_name(mut self, cookie_name: impl AsRef<str>) -> Self {
        self.cookie_name = cookie_name.as_ref().to_owned();
        self
    }

    /// Sets the domain for which the session cookie is valid. Defaults to `None`.
    pub fn with_cookie_domain(mut self, cookie_domain: impl AsRef<str>) -> Self {
        self.cookie_domain = Some(cookie_domain.as_ref().to_owned());
        self
    }

    /// Sets the same-site policy of the session cookie. Defaults to
    /// `SameSite::Strict`.
    /// For security reasons, do not change this.
    pub fn with_same_site_policy(mut self, policy: SameSite) -> Self {
        self.same_site_policy = policy;
        self
    }

    /// Sets the renewal strategy for sessions.
    /// See the members of [`SessionRenewalStrategy`] for more details.
    /// Defaults to [`AutomaticRenewal`](SessionRenewalStrategy::AutomaticRenewal) with a ttl of 24 hours
    /// and an automatic renewal delay of 4 hours.
    pub fn with_session_renewal_strategy(
        mut self,
        session_renewal_strategy: SessionRenewalStrategy,
    ) -> Self {
        *self.store.session_renewal_strategy_mut() = session_renewal_strategy;
        self
    }

    /// Sets the `secure` attribute for the session cookie. Defaults to `true`.
    /// For security reasons, do not set this to `false`.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    fn build_cookie(&self, cookie_value: String, expiry: SessionExpiry) -> Cookie<'static> {
        let mut cookie = Cookie::build((self.cookie_name.clone(), cookie_value))
            .http_only(true)
            .same_site(self.same_site_policy)
            .secure(self.secure)
            .path(self.cookie_path.clone())
            .build();

        match expiry {
            SessionExpiry::DateTime(expiry) => cookie.set_expires(Some(
                OffsetDateTime::from_unix_timestamp(expiry.timestamp()).unwrap(),
            )),
            SessionExpiry::Never => { /* no expiry by default */ }
        }

        if let Some(cookie_domain) = self.cookie_domain.clone() {
            cookie.set_domain(cookie_domain)
        }

        cookie
    }

    fn build_removal_cookie(&self) -> Cookie<'static> {
        let cookie = Cookie::build((self.cookie_name.clone(), ""))
            .http_only(true)
            .path(self.cookie_path.clone());

        let mut cookie = if let Some(cookie_domain) = self.cookie_domain.clone() {
            cookie.domain(cookie_domain)
        } else {
            cookie
        }
        .build();

        cookie.make_removal();

        cookie
    }
}

async fn load_or_create<
    SessionData: Default + Debug,
    SessionStoreConnection: SessionStoreConnector<SessionData>,
>(
    store: &SessionStore<SessionData, SessionStoreConnection>,
    cookie_value: Option<impl AsRef<str>>,
    connection: &mut SessionStoreConnection,
) -> (
    SessionHandle<SessionData>,
    Result<
        (),
        typed_session::Error<<SessionStoreConnection as SessionStoreConnector<SessionData>>::Error>,
    >,
) {
    let (session, result) = match cookie_value {
        Some(cookie_value) => match store.load_session(cookie_value, connection).await {
            Ok(session) => (session, Ok(())),
            Err(error) => (None, Err(error)),
        },
        None => (None, Ok(())),
    };

    (Arc::new(RwLock::new(session.unwrap_or_default())), result)
}

impl<Inner, SessionData, SessionStoreConnection: SessionStoreConnector<SessionData> + Clone>
    Layer<Inner> for SessionLayer<SessionData, SessionStoreConnection>
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

/// The error type for the session layer.
#[derive(Debug)]
pub enum SessionLayerError<SessionStoreConnectorError, InnerError> {
    /// An error occurred in the session store.
    SessionStore(typed_session::Error<SessionStoreConnectorError>),
    /// An error occurred in some inner service.
    Inner(InnerError),
}

impl<SessionStoreConnectorError: Display, InnerError: Display> Display
    for SessionLayerError<SessionStoreConnectorError, InnerError>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionLayerError::SessionStore(error) => write!(f, "session store error: {error}"),
            SessionLayerError::Inner(error) => write!(f, "{error}"),
        }
    }
}

impl<SessionStoreConnectorError: Debug + Display, InnerError: Debug + Display> std::error::Error
    for SessionLayerError<SessionStoreConnectorError, InnerError>
{
}

impl<
        Inner: 'static,
        RequestBody: Send + 'static,
        ResponseBody: Send,
        SessionData: Default + Debug + Send + Sync + 'static,
        SessionStoreConnection: SessionStoreConnector<SessionData> + Clone + Send + Sync + 'static,
    > Service<Request<RequestBody>> for Session<Inner, SessionData, SessionStoreConnection>
where
    Inner: Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + Send,
    Inner::Future: Send,
    <SessionStoreConnection as SessionStoreConnector<SessionData>>::Error: Send,
{
    type Response = Inner::Response;
    type Error = SessionLayerError<
        <SessionStoreConnection as SessionStoreConnector<SessionData>>::Error,
        Inner::Error,
    >;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(SessionLayerError::Inner)
    }

    fn call(&mut self, mut request: Request<RequestBody>) -> Self::Future {
        let session_layer = self.layer.clone();

        let inner = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, inner);

        let mut connection = request
            .extensions()
            .get::<SessionStoreConnection>()
            .expect("session service requires a session store connection in the extensions.")
            .clone();

        Box::pin(async move {
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

            let (session_handle, load_session_result) =
                load_or_create(&session_layer.store, cookie_value, &mut connection).await;
            if let Err(error) = load_session_result {
                tracing::warn!("Failed to load session from store: {error:?}");
            }

            request.extensions_mut().insert(session_handle.clone());
            let mut response = inner
                .oneshot(request)
                .await
                .map_err(SessionLayerError::Inner)?;

            let session = RwLock::into_inner(
                Arc::try_unwrap(session_handle).expect("Session handle still has owners."),
            );

            let store = &session_layer.store;
            match store.store_session(session, &mut connection).await {
                Ok(SessionCookieCommand::DoNothing) => {}
                Ok(SessionCookieCommand::Set {
                    cookie_value,
                    expiry,
                }) => {
                    let cookie = session_layer.build_cookie(cookie_value, expiry);

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
    use std::str::FromStr;
    use tower::{BoxError, Service, ServiceBuilder, ServiceExt};
    use typed_session::{DefaultLogger, NoLogger};

    use crate::{typed_session::MemoryStore, SessionHandle, SessionLayer};

    enum ExpectedResult {
        Some,
        None,
    }

    #[tokio::test]
    async fn sets_cookie_for_modified_session() {
        let store = MemoryStore::<(), _>::new();
        let session_layer: SessionLayer<(), MemoryStore<(), NoLogger>> = SessionLayer::new();
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(echo_with_session_change);

        let mut request = Request::get("/").body("").unwrap();
        request.extensions_mut().insert(store);

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        assert!(res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("id="))
    }

    #[tokio::test]
    async fn uses_valid_session() {
        let store = MemoryStore::<i32, _>::new();
        let session_layer: SessionLayer<i32, MemoryStore<i32, NoLogger>> = SessionLayer::new();
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let mut request = Request::get("/").body("").unwrap();
        request.extensions_mut().insert(store.clone());

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        assert_eq!(res.status(), StatusCode::OK);

        let counter = res.into_body();
        assert_eq!(counter, 1);

        let mut request = Request::get("/").body("").unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.to_owned());
        request.extensions_mut().insert(store);
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let counter = res.into_body();
        assert_eq!(counter, 2);
    }

    #[tokio::test]
    async fn multiple_cookies_in_single_header() {
        let store = MemoryStore::<i32, _>::new();
        let session_layer: SessionLayer<i32, MemoryStore<i32, NoLogger>> = SessionLayer::new();
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let mut request = Request::get("/").body("").unwrap();
        request.extensions_mut().insert(store.clone());

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        // build a Cookie header that contains two cookies: an unrelated dummy cookie,
        // and the given session cookie
        let request_cookie =
            HeaderValue::from_str(&format!("key=value; {}", session_cookie.to_str().unwrap()))
                .unwrap();

        assert_eq!(res.status(), StatusCode::OK);

        let counter = res.into_body();
        assert_eq!(counter, 1);

        let mut request = Request::get("/").body("").unwrap();
        request.headers_mut().insert(COOKIE, request_cookie);
        request.extensions_mut().insert(store);
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let counter = res.into_body();
        assert_eq!(counter, 2);
    }

    #[tokio::test]
    async fn multiple_cookie_headers() {
        let store = MemoryStore::<i32, _>::new();
        let session_layer: SessionLayer<i32, MemoryStore<i32, NoLogger>> = SessionLayer::new();
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let mut request = Request::get("/").body("").unwrap();
        request.extensions_mut().insert(store.clone());

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();
        let dummy_cookie = HeaderValue::from_str("key=value").unwrap();

        assert_eq!(res.status(), StatusCode::OK);

        let counter = res.into_body();
        assert_eq!(counter, 1);

        let mut request = Request::get("/").body("").unwrap();
        request.headers_mut().append(COOKIE, dummy_cookie);
        request.headers_mut().append(COOKIE, session_cookie);
        request.extensions_mut().insert(store);
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let counter = res.into_body();
        assert_eq!(counter, 2);
    }

    #[tokio::test]
    async fn no_cookie_stored_when_no_session_is_required() {
        let store = MemoryStore::<i32, _>::new();
        let session_layer: SessionLayer<i32, MemoryStore<i32, NoLogger>> = SessionLayer::new();
        let mut service = ServiceBuilder::new().layer(session_layer).service_fn(echo);

        let mut request = Request::get("/").body("").unwrap();
        request.extensions_mut().insert(store);

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
        let session_layer: SessionLayer<(), MemoryStore<(), DefaultLogger<()>>> =
            SessionLayer::new();
        let mut service = ServiceBuilder::new()
            .layer(&session_layer)
            .service_fn(echo_read_session);

        let mut request = Request::get("/").body("").unwrap();
        request.extensions_mut().insert(store.clone());

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
        let mut request = Request::get("/").body("").unwrap();
        request
            .headers_mut()
            .insert(COOKIE, "axum.sid=aW52YWxpZC1zZXNzaW9uLWlk".parse().unwrap());
        request.extensions_mut().insert(store);
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
        let session_layer: SessionLayer<(), MemoryStore<(), NoLogger>> = SessionLayer::new();
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(destroy);

        let mut request = Request::get("/").body("").unwrap();
        request.extensions_mut().insert(store.clone());

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let session_cookie = res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let mut request = Request::get("/destroy").body("").unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.parse().unwrap());
        request.extensions_mut().insert(store);
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(
            Cookie::from_str(res.headers().get(SET_COOKIE).unwrap().to_str().unwrap())
                .unwrap()
                .value(),
            ""
        );
    }

    async fn echo<Body>(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(req.into_body()))
    }

    async fn echo_read_session<Body>(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        {
            let session_handle = req.extensions().get::<SessionHandle<()>>().unwrap();
            let session = session_handle.write().await;
            let _ = session.data();
        }
        Ok(Response::new(req.into_body()))
    }

    async fn echo_with_session_change<Body>(
        req: Request<Body>,
    ) -> Result<Response<Body>, BoxError> {
        {
            let session_handle = req.extensions().get::<SessionHandle<()>>().unwrap();
            let mut session = session_handle.write().await;
            session.data_mut();
        }
        Ok(Response::new(req.into_body()))
    }

    async fn destroy<Body>(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        // Destroy the session if we received a session cookie.
        if req.headers().get(COOKIE).is_some() {
            let session_handle = req.extensions().get::<SessionHandle<()>>().unwrap();
            let mut session = session_handle.write().await;
            session.delete();
        } else {
            req.extensions()
                .get::<SessionHandle<()>>()
                .unwrap()
                .write()
                .await
                .data_mut();
        }

        Ok(Response::new(req.into_body()))
    }

    async fn increment<Body>(req: Request<Body>) -> Result<Response<i32>, BoxError> {
        let counter;

        {
            let session_handle = req.extensions().get::<SessionHandle<i32>>().unwrap();
            let mut session = session_handle.write().await;
            *session.data_mut() += 1;
            counter = *session.data();
        }

        Ok(Response::new(counter))
    }
}
