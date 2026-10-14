use std::io::{self};

use alloy_primitives::aliases::B32;

use crate::inbound_protocol::ResponseCode;

#[derive(thiserror::Error, Debug)]
pub enum ReqRespError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("Invalid data {0}")]
    InvalidData(String),

    #[error("Remote error [{code:?}]: {message}")]
    RemoteError { code: ResponseCode, message: String },

    #[error("Incomplete stream")]
    IncompleteStream,

    #[error("Stream timed out: {0}")]
    StreamTimedOut(String),

    #[error("Tokio timed out {0}")]
    TokioTimedOut(#[from] tokio::time::error::Elapsed),

    #[error("Disconnected")]
    Disconnected,

    #[error("Raw error message {0}")]
    RawError(String),

    /// The response is tagged with a valid fork digest of this network that predates the forks
    /// we can decode. Not evidence of a faulty peer.
    #[error("Response belongs to unsupported fork {0}")]
    UnsupportedFork(B32),
}

impl From<ssz::DecodeError> for ReqRespError {
    fn from(err: ssz::DecodeError) -> Self {
        ReqRespError::InvalidData(format!("Failed to decode ssz: {err:?}"))
    }
}
