pub mod app;
pub mod candidate;
pub mod perf;
pub mod rpc;

use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, TgsError>;

#[derive(Debug, Error)]
pub enum TgsError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}

impl From<&str> for TgsError {
    fn from(value: &str) -> Self {
        Self::Message(value.to_owned())
    }
}

impl From<String> for TgsError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}
