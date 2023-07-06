//! **Typed-session-axum** is a middleware providing cookie-based sessions for axum applications.
//!
//! [`SessionLayer`] provides client sessions via the [`typed_session`] crate.
//! Sessions are backed by cookies. These cookies are generated
//! when they are not found or are otherwise invalid. When a valid, known cookie
//! is received in a request, the session data is retrieved from the session store using this cookie.
//!
//! The middleware provides sessions via [`SessionHandle`]. Handlers use the
//! [`ReadableSession`](ReadableSession) and
//! [`WritableSession`](WritableSession) extractors to read
//! from and write to sessions respectively.
//!
//! The middleware expects a `SessionStoreConnection` to be present, which represents a connection
//! to a database used to store the sessions.
//! See [`SessionLayer::new`] for more details.
//!
//! # Example
//!
//! Using the middleware with axum is straightforward:
//!
//! ```rust,no_run
//! use axum::{routing::get, Router, error_handling::HandleErrorLayer, Extension};
//!  use tower::ServiceBuilder;
//! use typed_session_axum::{
//!     typed_session::{MemoryStore, NoLogger}, WritableSession, SessionLayer, SessionLayerError,
//! };
//! use std::fmt::Display;
//! use http::StatusCode;
//!
//! #[tokio::main]
//! async fn main() {
//!     let store = MemoryStore::<i32, _>::new(); // mock database connection for debugging purposes
//!     let session_layer = SessionLayer::<i32, MemoryStore<i32, NoLogger>>::new();
//!
//!     async fn handler(mut session: WritableSession<i32>) {
//!         *session.data_mut() = 42;
//!     }
//!
//!     async fn error_handler<SessionStoreConnectorError: Display, InnerError: Display>(
//!         error: SessionLayerError<SessionStoreConnectorError, InnerError>
//!     ) -> (StatusCode, String) {
//!         (
//!             StatusCode::INTERNAL_SERVER_ERROR,
//!             format!("Error: {error}"),
//!         )   
//!     }
//!
//!     let app = Router::new().route("/", get(handler)).layer(
//!         ServiceBuilder::new()
//!             .layer(HandleErrorLayer::new(error_handler)) // handle errors
//!             .layer(session_layer)
//!             .layer(Extension(store)) // provide a connection to the session database
//!     );
//!
//!     axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
//!         .serve(app.into_make_service())
//!         .await
//!         .unwrap();
//! }
//! ```
//!
//! This middleware may also be used as a generic [Tower](tower) middleware by making use
//! of the [`SessionHandle`] extension:
//!
//! ```rust
//! use std::convert::Infallible;
//!
//! use axum::http::header::SET_COOKIE;
//! use typed_session_axum::{typed_session::{MemoryStore, NoLogger}, SessionHandle, SessionLayer};
//! use http::{Request, Response};
//! use hyper::Body;
//! use rand::Rng;
//! use tower::{Service, ServiceBuilder, ServiceExt};
//!
//! async fn handle(request: Request<Body>) -> Result<Response<Body>, Infallible> {
//!     let session_handle = request.extensions().get::<SessionHandle<()>>().unwrap();
//!     let mut session = session_handle.write().await;
//!     // Use the session as you'd like.
//!     session.data_mut();
//!
//!     Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = MemoryStore::<(), _>::new(); // mock database connection for debugging purposes
//! let session_layer = SessionLayer::<(), MemoryStore<(), NoLogger>>::new();
//!
//! let mut service = ServiceBuilder::new()
//!     .layer(session_layer)
//!     .service_fn(handle);
//!
//! let mut request = Request::builder().body(Body::empty()).unwrap();
//! request.extensions_mut().insert(store); // provide a connection to the session database
//!
//! let response = service.ready().await?.call(request).await?;
//!
//! assert!(
//!     response
//!         .headers()
//!         .get(SET_COOKIE)
//!         .unwrap()
//!         .to_str()
//!         .unwrap()
//!         .starts_with("id=")
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
pub use session::{SessionHandle, SessionLayer, SessionLayerError};

mod extractors;
mod session;

pub use typed_session;

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
