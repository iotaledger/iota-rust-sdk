// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::ledger::{
    ApduAnswer, ApduCommand, ApduError, MaybeSendSync, Transport, TransportFuture,
    iota_crypto::DerivationPath,
};

use crate::{
    transaction_builder::signer::{TransactionSignerFn, TransactionSignerFnOutput},
    types::{
        address::Address,
        crypto::{Ed25519PublicKey, intent::PersonalMessage},
        object::Object,
        signature::UserSignature,
        transaction::Transaction,
    },
};

/// Error returned when communicating with a Ledger device fails.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
#[uniffi(flat_error)]
pub enum LedgerError {
    /// The user rejected the request on the device.
    #[error("{0}")]
    UserRefused(String),
    /// The device is locked.
    #[error("{0}")]
    DeviceLocked(String),
    /// The device runs another app than the IOTA app.
    #[error("{0}")]
    DeviceNotReady(String),
    /// No Ledger device is connected.
    #[error("{0}")]
    DeviceNotFound(String),
    /// The IOTA app is not installed on the device.
    #[error("{0}")]
    AppNotFound(String),
    /// The IOTA app cannot clear-sign the transaction, and blind signing is
    /// disabled in its settings.
    #[error("{0}")]
    BlindSigningDisabled(String),
    /// The device returns a different key for the signer's derivation path
    /// than when the signer was created, because another device is connected
    /// or the device was unlocked with a different seed or passphrase.
    #[error("{0}")]
    KeyMismatch(String),
    /// Any other failure.
    #[error("{0}")]
    Other(String),
}

impl From<iota_sdk::ledger::LedgerError> for LedgerError {
    fn from(error: iota_sdk::ledger::LedgerError) -> Self {
        use iota_sdk::ledger::LedgerError as E;

        let message = error.to_string();
        match error {
            E::Apdu(ApduError::UserRefused) => Self::UserRefused(message),
            E::Apdu(ApduError::DeviceLocked) => Self::DeviceLocked(message),
            E::Apdu(ApduError::DeviceNotReady) => Self::DeviceNotReady(message),
            E::DeviceNotFound => Self::DeviceNotFound(message),
            E::AppNotFound => Self::AppNotFound(message),
            E::BlindSigningDisabled => Self::BlindSigningDisabled(message),
            E::KeyMismatch => Self::KeyMismatch(message),
            _ => Self::Other(message),
        }
    }
}

fn parse_path(path: &str) -> Result<DerivationPath, LedgerError> {
    path.parse()
        .map_err(|e: iota_sdk::ledger::iota_crypto::DerivationPathError| {
            LedgerError::Other(e.to_string())
        })
}

#[cfg(feature = "ledger-hid")]
fn new_native_hid() -> Result<iota_sdk::ledger::Ledger, LedgerError> {
    Ok(iota_sdk::ledger::Ledger::new_native_hid()?)
}

// The constructor stays in builds without HID so that every native library of
// a binding package exposes the same functions as the bindings generated from
// the desktop build.
#[cfg(not(feature = "ledger-hid"))]
fn new_native_hid() -> Result<iota_sdk::ledger::Ledger, LedgerError> {
    Err(LedgerError::Other(
        "this build of the SDK cannot connect to Ledger devices over USB".to_owned(),
    ))
}

/// Error a `LedgerTransport` fails to exchange a command with.
// Not `LedgerError`: uniffi cannot pass a flat error from the host language to
// Rust.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum LedgerTransportError {
    /// No Ledger device is connected.
    #[error("Ledger device not found; connect the device")]
    DeviceNotFound,
    /// Any other failure.
    // Not `message`, which the Kotlin bindings cannot compile: it collides
    // with `Throwable.message`.
    #[error("{reason}")]
    Other { reason: String },
}

// uniffi reports any other exception a transport throws through this.
impl From<uniffi::UnexpectedUniFFICallbackError> for LedgerTransportError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Other {
            reason: error.reason,
        }
    }
}

impl From<LedgerTransportError> for iota_sdk::ledger::LedgerError {
    fn from(error: LedgerTransportError) -> Self {
        match error {
            LedgerTransportError::DeviceNotFound => Self::DeviceNotFound,
            LedgerTransportError::Other { reason } => Self::transport(reason),
        }
    }
}

/// A link to a Ledger device implemented in the host language, for the links
/// the SDK does not provide: Bluetooth through Ledger's mobile SDKs, or WebHID
/// and WebUSB in the browser.
#[uniffi::export(with_foreign)]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait LedgerTransport: MaybeSendSync {
    /// Send an APDU command (`cla ins p1 p2 len data`) to the device and
    /// return its answer: the response payload followed by the two-byte
    /// status word.
    ///
    /// Opening or closing an app closes the link on some transports. `Ledger`
    /// then calls this at intervals until the app answers, so re-establish a
    /// closed link here.
    async fn exchange(&self, apdu: Vec<u8>) -> Result<Vec<u8>, LedgerTransportError>;
}

struct ForeignTransport(Arc<dyn LedgerTransport>);

impl Transport for ForeignTransport {
    fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
        Box::pin(async move {
            let answer = self.0.exchange(command.to_bytes()).await?;
            ApduAnswer::from_bytes(answer)
        })
    }
}

/// The version of the IOTA app running on a Ledger device.
#[derive(uniffi::Record)]
pub struct LedgerAppVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl From<iota_sdk::ledger::AppVersion> for LedgerAppVersion {
    fn from(version: iota_sdk::ledger::AppVersion) -> Self {
        Self {
            major: version.major(),
            minor: version.minor(),
            patch: version.patch(),
        }
    }
}

/// A connection to the IOTA app on a Ledger device.
///
/// Every call completes once the device answers, which for address
/// verification includes waiting for the user to confirm on the device. Calls
/// on the same `Ledger`, including through the `LedgerSigner`s created from
/// it, run one at a time.
#[derive(uniffi::Object)]
pub struct Ledger(iota_sdk::ledger::Ledger);

impl From<iota_sdk::ledger::Ledger> for Ledger {
    fn from(ledger: iota_sdk::ledger::Ledger) -> Self {
        Self(ledger)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl Ledger {
    /// Connect to the first Ledger device attached over USB.
    ///
    /// Fails in builds of the SDK without USB support, such as those for
    /// Android, iOS and the web.
    #[uniffi::constructor]
    pub fn native_hid() -> Result<Self, LedgerError> {
        new_native_hid().map(Self::from)
    }

    /// Connect to the APDU port of a Speculos emulator (by default this is
    /// `127.0.0.1:9999` in the emulator).
    ///
    /// Calls through this connection block the thread running them until the
    /// emulator answers, and fail in the WASM bindings, which have no TCP
    /// sockets.
    #[uniffi::constructor]
    pub fn speculos(host: String, port: u16) -> Self {
        iota_sdk::ledger::Ledger::new_speculos(&host, port).into()
    }

    /// Communicate with the device through a transport implemented in the
    /// host language.
    ///
    /// `open_app` closes whichever other app the transport reports as
    /// running, so do not call it on an emulator that reports a placeholder
    /// app name, such as Speculos started without
    /// `SPECULOS_APPNAME=IOTA:<version>`: it ends the emulated app.
    #[uniffi::constructor]
    pub fn from_transport(transport: Arc<dyn LedgerTransport>) -> Self {
        iota_sdk::ledger::Ledger::new(ForeignTransport(transport)).into()
    }

    /// Check whether the IOTA app is the app running on the device.
    ///
    /// Speculos reports a placeholder app name unless started with
    /// `SPECULOS_APPNAME=IOTA:<version>`, so this returns `false` there.
    pub async fn is_app_open(&self) -> Result<bool, LedgerError> {
        Ok(self.0.is_app_open().await?)
    }

    /// Open the IOTA app, from the dashboard or by closing another app first.
    ///
    /// Does nothing if the IOTA app is already running, or on a `speculos`
    /// connection.
    pub async fn open_app(&self) -> Result<(), LedgerError> {
        Ok(self.0.open_app().await?)
    }

    /// Close the app running on the device and return to the dashboard.
    ///
    /// On Speculos, this ends the emulated app.
    pub async fn exit_app(&self) -> Result<(), LedgerError> {
        Ok(self.0.exit_app().await?)
    }

    /// Read the version of the IOTA app.
    pub async fn version(&self) -> Result<LedgerAppVersion, LedgerError> {
        Ok(self.0.version().await?.into())
    }

    /// Read the public key at a derivation path such as
    /// `m/44'/4218'/0'/0'/0'`.
    pub async fn get_public_key(&self, path: String) -> Result<Ed25519PublicKey, LedgerError> {
        let path = parse_path(&path)?;
        Ok(self.0.get_public_key(&path).await?.into())
    }

    /// Show the address at a derivation path on the device for the user to
    /// confirm, and return its public key.
    pub async fn verify_address(&self, path: String) -> Result<Ed25519PublicKey, LedgerError> {
        let path = parse_path(&path)?;
        Ok(self.0.verify_address(&path).await?.into())
    }

    /// Create a signer for the key at a derivation path such as
    /// `m/44'/4218'/0'/0'/0'`, reading its public key from the device.
    ///
    /// The signer shares this `Ledger`'s connection, which stays usable.
    pub async fn signer(&self, path: String) -> Result<LedgerSigner, LedgerError> {
        let path = parse_path(&path)?;
        Ok(LedgerSigner(self.0.clone().into_signer(path).await?))
    }
}

/// Signs with the key at one derivation path on a Ledger device.
///
/// Before each signature it reads the public key again and fails with
/// `KeyMismatch` if it differs, which happens when another device is connected
/// or the device was unlocked with a different seed or passphrase.
///
/// Use `TransactionSigner.from_ledger` to sign with it through the transaction
/// builder, which passes it the transaction's objects so the device shows what
/// the transaction does.
#[derive(Debug, uniffi::Object)]
pub struct LedgerSigner(pub(crate) iota_sdk::ledger::LedgerSigner);

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl LedgerSigner {
    /// The derivation path of the signing key.
    pub fn path(&self) -> String {
        self.0.path().to_string()
    }

    /// The public key that signs.
    pub fn public_key(&self) -> Ed25519PublicKey {
        (*self.0.public_key()).into()
    }

    /// The address of the signing key.
    pub fn address(&self) -> Address {
        self.0.address().into()
    }

    /// Sign a transaction without its input objects. Fails with
    /// `BlindSigningDisabled` if blind signing is disabled in the IOTA app's
    /// settings.
    pub async fn sign_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<UserSignature, LedgerError> {
        Ok(self.0.sign_transaction(&transaction.0).await?.into())
    }

    /// Sign a transaction, passing its input objects so the device can
    /// clear-sign it. Falls back to blind signing with an IOTA app older than
    /// 1.0.
    pub async fn sign_transaction_with_objects(
        &self,
        transaction: &Transaction,
        objects: Vec<Arc<Object>>,
    ) -> Result<UserSignature, LedgerError> {
        let objects = objects
            .iter()
            .map(|object| object.0.clone())
            .collect::<Vec<_>>();
        Ok(self
            .0
            .sign_transaction_with_objects(&transaction.0, &objects)
            .await?
            .into())
    }

    /// Sign a personal message.
    pub async fn sign_personal_message(
        &self,
        message: &PersonalMessage,
    ) -> Result<UserSignature, LedgerError> {
        Ok(self.0.sign_personal_message(&message.0).await?.into())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TransactionSignerFn for LedgerSigner {
    async fn sign(
        &self,
        transaction: Arc<Transaction>,
    ) -> crate::error::Result<TransactionSignerFnOutput> {
        let signature = self.0.sign_transaction(&transaction.0).await?;
        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature.into()),
        })
    }

    fn uses_objects(&self) -> bool {
        true
    }

    async fn sign_with_objects(
        &self,
        transaction: Arc<Transaction>,
        objects: Vec<Arc<Object>>,
    ) -> crate::error::Result<TransactionSignerFnOutput> {
        let objects = objects
            .iter()
            .map(|object| object.0.clone())
            .collect::<Vec<_>>();
        let signature = iota_sdk::transaction_builder::TransactionSigner::sign_with_objects(
            &self.0,
            &transaction.0,
            &objects,
        )
        .await?;
        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use iota_sdk::{
        ledger::{ApduAnswer, ApduCommand, Transport, TransportFuture},
        transaction_builder::TransactionSigner as _,
    };

    use super::*;
    use crate::transaction_builder::signer::TransactionSigner;

    const PATH: &str = "m/44'/4218'/0'/0'/0'";

    /// Answers version and public key requests at once, or fails every command
    /// while `connected` is unset.
    struct FakeDevice {
        connected: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Transport for FakeDevice {
        fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
            Box::pin(async move {
                if !self.connected.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(iota_sdk::ledger::LedgerError::DeviceNotFound);
                }
                let public_key = iota_sdk::types::Ed25519PublicKey::new([7; 32]);
                let result = match command.ins() {
                    0x00 => vec![1, 0, 1],
                    0x02 => [
                        &[32][..],
                        public_key.bytes(),
                        &[32],
                        public_key.derive_address().as_bytes(),
                    ]
                    .concat(),
                    ins => panic!("unexpected instruction {ins:#04x}"),
                };
                ApduAnswer::from_bytes([&[1][..], &result, &[0x90, 0x00]].concat())
            })
        }
    }

    fn ledger(connected: bool) -> (Ledger, Arc<std::sync::atomic::AtomicBool>) {
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(connected));
        let ledger = iota_sdk::ledger::Ledger::new(FakeDevice {
            connected: connected.clone(),
        });
        (ledger.into(), connected)
    }

    #[test]
    fn ledger_stays_usable_after_creating_a_signer() {
        let (ledger, connected) = ledger(false);
        assert!(matches!(
            block_on(ledger.signer(PATH.to_owned())),
            Err(LedgerError::DeviceNotFound(_))
        ));

        connected.store(true, std::sync::atomic::Ordering::SeqCst);
        block_on(ledger.signer(PATH.to_owned())).unwrap();
        block_on(ledger.version()).unwrap();
    }

    #[test]
    fn transaction_signer_asks_for_objects() {
        let (ledger, _) = ledger(true);
        let signer = block_on(ledger.signer(PATH.to_owned())).unwrap();
        assert!(TransactionSigner::from_ledger(Arc::new(signer)).uses_objects());
    }

    /// Implements the transport the way a host language does: records the
    /// commands it receives and answers each with `answer`.
    struct HostTransport {
        received: std::sync::Mutex<Vec<Vec<u8>>>,
        answer: fn() -> Result<Vec<u8>, LedgerTransportError>,
    }

    #[async_trait::async_trait]
    impl LedgerTransport for HostTransport {
        async fn exchange(&self, apdu: Vec<u8>) -> Result<Vec<u8>, LedgerTransportError> {
            self.received.lock().unwrap().push(apdu);
            (self.answer)()
        }
    }

    fn host_transport(answer: fn() -> Result<Vec<u8>, LedgerTransportError>) -> Arc<HostTransport> {
        Arc::new(HostTransport {
            received: Default::default(),
            answer,
        })
    }

    #[test]
    fn host_transport_exchanges_commands_as_sent_over_the_wire() {
        // Version 1.0.1 as a final block protocol result, then the status word
        let transport = host_transport(|| Ok(vec![1, 1, 0, 1, 0x90, 0x00]));
        let ledger = Ledger::from_transport(transport.clone());

        let version = block_on(ledger.version()).unwrap();
        assert_eq!((version.major, version.minor, version.patch), (1, 0, 1));
        // cla, ins, p1, p2 and length, then the block protocol start byte and
        // the hash that stands for an empty parameter
        assert_eq!(
            *transport.received.lock().unwrap(),
            [[&[0, 0, 0, 0, 33, 0][..], &[0; 32]].concat()]
        );
    }

    #[test]
    fn host_transport_errors_reach_the_caller() {
        let ledger =
            Ledger::from_transport(host_transport(|| Err(LedgerTransportError::DeviceNotFound)));
        assert!(matches!(
            block_on(ledger.version()),
            Err(LedgerError::DeviceNotFound(_))
        ));

        let ledger = Ledger::from_transport(host_transport(|| {
            Err(LedgerTransportError::Other {
                reason: "link closed".to_owned(),
            })
        }));
        assert!(matches!(
            block_on(ledger.version()),
            Err(LedgerError::Other(message)) if message == "link closed"
        ));

        // A status word other than success
        let ledger = Ledger::from_transport(host_transport(|| Ok(vec![0x55, 0x15])));
        assert!(matches!(
            block_on(ledger.version()),
            Err(LedgerError::DeviceLocked(_))
        ));
    }
}
