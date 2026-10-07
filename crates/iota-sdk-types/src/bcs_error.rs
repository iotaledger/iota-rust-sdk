// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Error returned when BCS serialization or deserialization fails.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct BcsError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl BcsError {
    /// Wraps the error returned by a BCS serializer or deserializer.
    pub fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn display_matches_source() {
        let source = bcs::from_bytes::<u64>(&[0u8; 9]).unwrap_err();
        assert_eq!(
            BcsError::new(source.clone()).to_string(),
            source.to_string()
        );
    }
}
