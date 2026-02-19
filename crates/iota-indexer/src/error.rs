use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid {field}: {reason}")]
    Validation { field: &'static str, reason: String },

    #[error("checkpoint {0} not found on RPC")]
    CheckpointNotFound(u64),

    #[error("sqlx error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("sdk error: {0}")]
    Sdk(#[from] iota_sdk::graphql_client::error::Error),

    #[error("serde json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("bcs encode/decode error: {0}")]
    Bcs(#[from] bcs::Error),

    #[error("parse int error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

impl AppError {
    pub fn validation(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Validation {
            field,
            reason: reason.into(),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
