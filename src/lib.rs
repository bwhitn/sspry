pub mod app;
pub mod candidate;
pub mod grpc;
pub mod perf;
pub mod rpc;

use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SspryError>;

#[derive(Debug, Error)]
pub enum SspryError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}

impl From<&str> for SspryError {
    fn from(value: &str) -> Self {
        Self::Message(value.to_owned())
    }
}

impl From<String> for SspryError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}
