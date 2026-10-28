// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Ledger errors.

use iota_types::BcsError;

use crate::AppVersion;

/// Error returned when communicating with a Ledger device fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// The device answered a command with an error.
    #[error(transparent)]
    Apdu(#[from] ApduError),
    /// The IOTA app is not installed on the device.
    #[error("IOTA app not found; install the IOTA app on the Ledger device")]
    AppNotFound,
    /// The IOTA app cannot clear-sign the transaction, and blind signing is
    /// disabled in its settings.
    #[error(
        "transaction cannot be clear-signed and blind signing is disabled in the IOTA app's settings"
    )]
    BlindSigningDisabled,
    /// The IOTA app is older than 1.0, which introduced clear signing.
    #[error("IOTA app {0} does not support clear signing; update the app")]
    ClearSigningUnsupported(AppVersion),
    /// The IOTA app only allows paths under `m/44'/4218'` and `m/44'/1'`.
    #[error("the IOTA app does not allow this derivation path")]
    DerivationPathNotAllowed,
    /// No Ledger device is connected.
    #[error("Ledger device not found; connect the device")]
    DeviceNotFound,
    /// The device's response could not be decoded.
    #[error("invalid response from the device: {0}")]
    InvalidResponse(String),
    /// The device returns a different key for the signer's derivation path
    /// than when the signer was created, because another device is connected
    /// or the device was unlocked with a different seed or passphrase.
    #[error(
        "the device returned a different key for the signer's derivation path; use the same device, seed and passphrase as when the signer was created"
    )]
    KeyMismatch,
    /// A command payload exceeds what the protocol can encode.
    #[error("payload is too long for the device")]
    PayloadTooLong,
    /// A transaction, message or object could not be serialized.
    #[error(transparent)]
    Serialization(BcsError),
    /// The transport failed to exchange a command with the device.
    #[error(transparent)]
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl LedgerError {
    /// Create a transport error from a message or from an underlying error.
    pub fn transport(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Transport(source.into())
    }

    pub(crate) fn invalid_response(message: impl Into<String>) -> Self {
        Self::InvalidResponse(message.into())
    }
}

/// Error the device answered a command with, as reported by the APDU status
/// word.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ApduError {
    /// The device is locked.
    #[error("device locked; unlock the Ledger device")]
    DeviceLocked,
    /// The device runs another app than the IOTA app.
    #[error("device not ready; open the IOTA app on the Ledger device")]
    DeviceNotReady,
    /// The app on the device panicked.
    #[error("device panic")]
    DevicePanic,
    /// A status word without a dedicated variant.
    #[error("device returned status word {0:#06x}")]
    Other(u16),
    /// The user rejected the request on the device.
    #[error("the user refused the operation on the device")]
    UserRefused,
}

impl ApduError {
    /// Map an APDU status word to an error, or `None` for success.
    pub(crate) fn from_status_word(sw: u16) -> Option<Self> {
        Some(match sw {
            0x9000 => return None,
            0x5515 => Self::DeviceLocked,
            0xe000 => Self::DevicePanic,
            // User cancelled, user denied
            0x6985 | 0x5501 => Self::UserRefused,
            // Bad class, instruction or parameters: another app is running
            0x6e00..=0x6e02 => Self::DeviceNotReady,
            sw => Self::Other(sw),
        })
    }
}
