//! Extractors for sessions.

use async_trait::async_trait;
use std::ops::{Deref, DerefMut};

use crate::session::SessionHandle;
use axum::{extract::FromRequestParts, http::request::Parts, Extension};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard};

// use crate::SessionHandle;

/// An extractor which provides a readable session. Sessions may have many
/// readers.
#[derive(Debug)]
pub struct ReadableSession<Data> {
    session: OwnedRwLockReadGuard<typed_session::Session<Data>>,
}

impl<Data> Deref for ReadableSession<Data> {
    type Target = OwnedRwLockReadGuard<typed_session::Session<Data>>;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

#[async_trait]
impl<S, Data: Send + Sync + 'static> FromRequestParts<S> for ReadableSession<Data>
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Extension(session_handle): Extension<SessionHandle<Data>> =
            Extension::from_request_parts(parts, state)
                .await
                .expect("Session extension missing. Is the session layer installed?");
        let session = session_handle.read_owned().await;

        Ok(Self { session })
    }
}

/// An extractor which provides a writable session. Sessions may have only one
/// writer.
#[derive(Debug)]
pub struct WritableSession<Data> {
    session: OwnedRwLockWriteGuard<typed_session::Session<Data>>,
}

impl<Data> Deref for WritableSession<Data> {
    type Target = OwnedRwLockWriteGuard<typed_session::Session<Data>>;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl<Data> DerefMut for WritableSession<Data> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
    }
}

#[async_trait]
impl<S, Data: Send + Sync + 'static> FromRequestParts<S> for WritableSession<Data>
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Extension(session_handle): Extension<SessionHandle<Data>> =
            Extension::from_request_parts(parts, state)
                .await
                .expect("Session extension missing. Is the session layer installed?");
        let session = session_handle.write_owned().await;

        Ok(Self { session })
    }
}
