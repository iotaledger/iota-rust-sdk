// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Defines the [`TransactionSigner`] trait, which allows users to implement any
//! type which can sign a transaction asynchronously.

use std::future::Future;

use iota_crypto::{
    IotaSigner, SignatureError, ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey,
    secp256r1::Secp256r1PrivateKey, simple::SimpleKeypair,
};
use iota_types::{MoveAuthenticator, Transaction, UserSignature};

/// Defines a type which can sign a transaction asynchronously.
///
/// This trait can be implemented downstream to enable signing when using the
/// [`TransactionBuilder`](crate::TransactionBuilder)
/// [`execute`](crate::TransactionBuilder::execute) function.
pub trait TransactionSigner {
    /// The error that can occur during signing.
    type Error: 'static + std::error::Error + Send + Sync;

    /// Sign a transaction and return a [`UserSignature`].
    fn sign(
        &self,
        transaction: &Transaction,
    ) -> impl Future<Output = Result<UserSignature, Self::Error>>;
}

macro_rules! impl_basic_signer {
    ($($signer:ident),*) => {
        $(
        impl TransactionSigner for $signer {
            type Error = SignatureError;

            async fn sign(&self, transaction: &Transaction) -> Result<UserSignature, Self::Error> {
                self.sign_transaction(transaction)
            }
        }
        )*
    };
}

impl_basic_signer!(
    Ed25519PrivateKey,
    Secp256k1PrivateKey,
    Secp256r1PrivateKey,
    SimpleKeypair
);

impl TransactionSigner for MoveAuthenticator {
    type Error = SignatureError;

    async fn sign(&self, _transaction: &Transaction) -> Result<UserSignature, Self::Error> {
        Ok(UserSignature::MoveAuthenticator(self.clone()))
    }
}

#[cfg(feature = "ledger")]
mod ledger {
    use iota_ledger::{LedgerError, LedgerSigner, LedgerSignerWithClient};
    use iota_types::{
        Input, Object, ObjectId, Transaction, TransactionKind, UserSignature, Version,
    };

    use super::TransactionSigner;
    use crate::TransactionBuilderLedgerClient;

    /// Signs without the transaction's input objects, so the device only signs
    /// when blind signing is enabled in the IOTA app's settings. Pair the
    /// signer with a client through [`LedgerSigner::with_client`] to
    /// clear-sign instead.
    ///
    /// With the USB HID and Speculos transports, signing blocks the task while
    /// the user confirms on the device.
    impl TransactionSigner for LedgerSigner {
        type Error = LedgerError;

        async fn sign(&self, transaction: &Transaction) -> Result<UserSignature, Self::Error> {
            self.sign_transaction(transaction).await
        }
    }

    /// Fetches the transaction's gas coins and immutable or owned inputs at
    /// their versions through the client, so the device can show what the
    /// transaction does. Falls back to blind signing, with a warning, when
    /// the objects cannot be fetched or the IOTA app cannot clear-sign.
    ///
    /// With the USB HID and Speculos transports, signing blocks the task while
    /// the user confirms on the device.
    impl<C: TransactionBuilderLedgerClient> TransactionSigner for LedgerSignerWithClient<C> {
        type Error = LedgerError;

        async fn sign(&self, transaction: &Transaction) -> Result<UserSignature, Self::Error> {
            let objects = match input_objects(self.client(), transaction).await {
                Ok(objects) => objects,
                Err(error) => {
                    tracing::warn!(
                        "could not fetch the transaction's input objects, blind signing instead: {error}"
                    );
                    return self.signer().sign_transaction(transaction).await;
                }
            };
            match self
                .signer()
                .sign_transaction_with_objects(transaction, &objects)
                .await
            {
                Err(LedgerError::ClearSigningUnsupported(version)) => {
                    tracing::warn!("IOTA app {version} cannot clear-sign, blind signing instead");
                    self.signer().sign_transaction(transaction).await
                }
                result => result,
            }
        }
    }

    /// Fetch the gas coins and the immutable or owned inputs of `transaction`
    /// at the versions it references.
    async fn input_objects<C: TransactionBuilderLedgerClient>(
        client: &C,
        transaction: &Transaction,
    ) -> Result<Vec<Object>, String> {
        let transaction = match transaction {
            Transaction::V1(transaction) => transaction,
            _ => unimplemented!("a new Transaction enum variant was added and needs to be handled"),
        };
        let mut ids = transaction
            .gas_payment
            .objects
            .iter()
            .map(|object| (object.object_id, Some(object.version)))
            .collect::<Vec<(ObjectId, Option<Version>)>>();
        if let TransactionKind::Programmable(programmable) = &transaction.kind {
            for input in &programmable.inputs {
                match input {
                    Input::ImmutableOrOwned(object) => {
                        ids.push((object.object_id, Some(object.version)))
                    }
                    Input::Pure(_) | Input::Shared(_) | Input::Receiving(_) => {}
                    _ => {
                        unimplemented!("a new Input enum variant was added and needs to be handled")
                    }
                }
            }
        }

        client
            .objects_by_id(&ids)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .zip(&ids)
            .map(|(object, (id, version))| {
                object.ok_or_else(|| format!("object {id} at version {version:?} not found"))
            })
            .collect()
    }

    #[cfg(all(test, feature = "test-client", not(target_arch = "wasm32")))]
    mod tests {
        use std::sync::{Arc, Mutex};

        use iota_ledger::{ApduAnswer, ApduCommand, Ledger, Transport, TransportFuture};
        use iota_types::{Address, Ed25519PublicKey, ObjectId, StructTag, Version};

        use super::*;
        use crate::{ObjectsPage, ProtocolConfig, TestClient, TestClientError};

        /// An IOTA plain transfer from the IOTA app's ragger tests.
        const TRANSACTION: &str = "00000100201b3669e321893ee49c387a08fc251dbfff37cd2a981e6c473a5b2afde19d363e010101000100000f58eb1351454d623a6a4366198d6cd5aa4a12a12a3caefb501476e06d8bd5b6011eec6c32ef36467331fb7b088b4acb1ce46f736354308e03ff6ce913a42734e2860000000000000020c7ebc6c4430b3cf7e58d75ab53ddb9180274def63b1ab5619fbdb7096cdbd7120f58eb1351454d623a6a4366198d6cd5aa4a12a12a3caefb501476e06d8bd5b6e80300000000000040420f000000000000";

        /// Answers each command with its final result at once and records how
        /// many parameters each signing request carries: three when the input
        /// objects are sent, two otherwise.
        struct FakeDevice {
            version: [u8; 3],
            sign_parameters: Arc<Mutex<Vec<usize>>>,
        }

        impl Transport for FakeDevice {
            fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
                Box::pin(async move {
                    let public_key = Ed25519PublicKey::new([7; 32]);
                    let result = match command.ins() {
                        0x00 => self.version.to_vec(),
                        0x02 => [
                            &[32][..],
                            public_key.bytes(),
                            &[32],
                            public_key.derive_address().as_bytes(),
                        ]
                        .concat(),
                        0x03 => {
                            // the start request is a tag byte and one hash per
                            // parameter
                            let parameters = (command.data().len() - 1) / 32;
                            self.sign_parameters.lock().unwrap().push(parameters);
                            vec![9; 64]
                        }
                        ins => panic!("unexpected instruction {ins:#04x}"),
                    };
                    ApduAnswer::from_bytes([&[1][..], &result, &[0x90, 0x00]].concat())
                })
            }
        }

        /// A client whose object lookups fail.
        struct FailingClient;

        impl crate::TransactionBuilderClientBase for FailingClient {
            type Error = TestClientError;
        }

        impl TransactionBuilderLedgerClient for FailingClient {
            async fn object(
                &self,
                _: ObjectId,
                _: impl Into<Option<Version>>,
            ) -> Result<Option<Object>, Self::Error> {
                Err(TestClientError("unreachable node".to_owned()))
            }

            async fn objects(
                &self,
                _: Option<StructTag>,
                _: Address,
                _: Option<Vec<u8>>,
                _: Option<usize>,
            ) -> Result<ObjectsPage, Self::Error> {
                unimplemented!()
            }

            async fn protocol_config(&self) -> Result<ProtocolConfig, Self::Error> {
                unimplemented!()
            }

            async fn reference_gas_price(
                &self,
                _: impl Into<Option<u64>>,
            ) -> Result<Option<u64>, Self::Error> {
                unimplemented!()
            }
        }

        async fn sign_parameters(
            version: [u8; 3],
            sign: impl AsyncFnOnce(LedgerSigner, &Transaction),
        ) -> Vec<usize> {
            let sign_parameters = Arc::new(Mutex::new(Vec::new()));
            let signer = Ledger::new(FakeDevice {
                version,
                sign_parameters: sign_parameters.clone(),
            })
            .into_signer("m/44'/4218'/0'/0'/0'".parse().unwrap())
            .await
            .unwrap();
            let transaction = bcs::from_bytes(&hex_decode(TRANSACTION)).unwrap();
            sign(signer, &transaction).await;
            sign_parameters.lock().unwrap().clone()
        }

        fn hex_decode(hex: &str) -> Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        }

        #[tokio::test]
        async fn blind_signs_without_a_client() {
            let parameters = sign_parameters([1, 0, 1], async |signer, transaction| {
                signer.sign(transaction).await.unwrap();
            })
            .await;
            assert_eq!(parameters, [2]);
        }

        #[tokio::test]
        async fn clear_signs_with_a_client() {
            let parameters = sign_parameters([1, 0, 1], async |signer, transaction| {
                signer
                    .with_client(TestClient)
                    .sign(transaction)
                    .await
                    .unwrap();
            })
            .await;
            assert_eq!(parameters, [3]);
        }

        #[tokio::test]
        async fn blind_signs_when_objects_cannot_be_fetched() {
            let parameters = sign_parameters([1, 0, 1], async |signer, transaction| {
                signer
                    .with_client(FailingClient)
                    .sign(transaction)
                    .await
                    .unwrap();
            })
            .await;
            assert_eq!(parameters, [2]);
        }

        #[tokio::test]
        async fn blind_signs_when_the_app_cannot_clear_sign() {
            let parameters = sign_parameters([0, 9, 2], async |signer, transaction| {
                signer
                    .with_client(TestClient)
                    .sign(transaction)
                    .await
                    .unwrap();
            })
            .await;
            assert_eq!(parameters, [2]);
        }
    }
}
