// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::grpc_client::GrpcError;

/// A gRPC status code, as reported by the server for a failed item of a
/// batched call.
///
/// See <https://grpc.io/docs/guides/status-codes/> for the meaning of each
/// code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum GrpcStatusCode {
    Ok,
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl GrpcStatusCode {
    /// The status code of an item error, or `None` if the error did not come
    /// from the server.
    pub(crate) fn of(error: &GrpcError) -> Option<Self> {
        match error {
            GrpcError::Server(status) => Some(status.code.into()),
            _ => None,
        }
    }
}

impl From<i32> for GrpcStatusCode {
    fn from(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Cancelled,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use iota_sdk::grpc_client::{GrpcError, RpcStatus};

    use super::GrpcStatusCode;

    #[test]
    fn server_error_carries_its_code() {
        let mut status = RpcStatus::default();
        status.code = 5;

        assert_eq!(
            GrpcStatusCode::of(&GrpcError::Server(status)),
            Some(GrpcStatusCode::NotFound)
        );
    }

    #[test]
    fn client_error_has_no_code() {
        assert_eq!(GrpcStatusCode::of(&GrpcError::EmptyRequest), None);
    }

    #[test]
    fn unrecognized_code_is_unknown() {
        assert_eq!(GrpcStatusCode::from(42), GrpcStatusCode::Unknown);
    }
}
