//! typed-session-axum is a middleware providing cookie-based sessions for axum
//! applications.
//!
//! [`SessionLayer`] provides client sessions via [`async_session`]. Sessions
//! are backed by cryptographically signed cookies. These cookies are generated
//! when they are not found or are otherwise invalid. When a valid, known cookie
//! is received in a request, the session is retrieved using this cookie. The
//! middleware provides sessions via [`SessionHandle`]. Handlers use the
//! [`ReadableSession`](ReadableSession) and
//! [`WritableSession`](WritableSession) extractors to read
//! from and write to sessions respectively.
//!
//! # Example
//!
//! Using the middleware with axum is straightforward:
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use typed_session_axum::{
//!     typed_session::MemoryStore, WritableSession, SessionLayer,
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     let store = MemoryStore::<i32>::new();
//!     let session_layer = SessionLayer::new(store);
//!
//!     async fn handler(mut session: WritableSession<i32>) {
//!         *session.data_mut() = 42;
//!     }
//!
//!     let app = Router::new().route("/", get(handler)).layer(session_layer);
//!
//!     axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
//!         .serve(app.into_make_service())
//!         .await
//!         .unwrap();
//! }
//! ```
//!
//! This middleware may also be used as a generic Tower middleware by making use
//! of the [`SessionHandle`] extension:
//!
//! ```rust
//! use std::convert::Infallible;
//!
//! use axum::http::header::SET_COOKIE;
//! use typed_session_axum::{typed_session::MemoryStore, SessionHandle, SessionLayer};
//! use http::{Request, Response};
//! use hyper::Body;
//! use rand::Rng;
//! use tower::{Service, ServiceBuilder, ServiceExt};
//!
//! async fn handle(request: Request<Body>) -> Result<Response<Body>, Infallible> {
//!     let session_handle = request.extensions().get::<SessionHandle<()>>().unwrap();
//!     let session = session_handle.read().await;
//!     // Use the session as you'd like.
//!
//!     Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = MemoryStore::<()>::new();
//! let session_layer = SessionLayer::new(store);
//!
//! let mut service = ServiceBuilder::new()
//!     .layer(session_layer)
//!     .service_fn(handle);
//!
//! let request = Request::builder().body(Body::empty()).unwrap();
//!
//! let response = service.ready().await?.call(request).await?;
//!
//! assert_eq!(
//!     response
//!         .headers()
//!         .get(SET_COOKIE)
//!         .unwrap()
//!         .to_str()
//!         .unwrap()
//!         .split("=")
//!         .collect::<Vec<_>>()[0],
//!     "id"
//! );
//!
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(
    future_incompatible,
    missing_debug_implementations,
    nonstandard_style,
    missing_docs,
    unreachable_pub,
    missing_copy_implementations,
    unused_qualifications
)]

pub use extractors::{ReadableSession, WritableSession};
pub use session::{SessionHandle, SessionLayer};

mod extractors;
mod session;

pub use typed_session;
