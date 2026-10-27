// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Defines the [`TransactionSigner`] trait, which allows users to implement any
//! type which can sign a transaction asynchronously.

use std::future::Future;

use iota_crypto::{
    IotaSigner, SignatureError, ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey,
    secp256r1::Secp256r1PrivateKey, simple::SimpleKeypair,
};
use iota_types::{MoveAuthenticator, Object, Transaction, UserSignature};

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

    /// Whether the signer uses the objects the transaction reads, such as a
    /// hardware wallet showing what the transaction does. When `true`, the
    /// builder gathers them for [`sign_with_objects`](Self::sign_with_objects).
    fn uses_objects(&self) -> bool {
        false
    }

    /// Sign a transaction given the objects it reads: its gas coins and
    /// immutable, owned or receiving inputs at the versions it references, and
    /// its shared inputs as the builder fetched them, which may change before
    /// the transaction executes. `objects` is empty when the signer does not
    /// use them. The default ignores them and calls [`sign`](Self::sign).
    fn sign_with_objects(
        &self,
        transaction: &Transaction,
        _objects: &[Object],
    ) -> impl Future<Output = Result<UserSignature, Self::Error>> {
        self.sign(transaction)
    }
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
    use std::collections::HashSet;

    use iota_ledger::{LedgerError, LedgerSigner};
    use iota_types::{Input, Object, Transaction, TransactionKind, UserSignature};

    use super::TransactionSigner;

    /// Clear-signs with the objects the builder gathers, so the device shows
    /// what the transaction does. Without them, or with an IOTA app too old to
    /// clear-sign, it blind-signs with a warning, which the app only allows
    /// when blind signing is enabled in its settings.
    ///
    /// With the Speculos transport, signing blocks the thread polling it until
    /// the emulator answers.
    impl TransactionSigner for LedgerSigner {
        type Error = LedgerError;

        async fn sign(&self, transaction: &Transaction) -> Result<UserSignature, Self::Error> {
            self.sign_transaction(transaction).await
        }

        fn uses_objects(&self) -> bool {
            true
        }

        async fn sign_with_objects(
            &self,
            transaction: &Transaction,
            objects: &[Object],
        ) -> Result<UserSignature, Self::Error> {
            if objects.is_empty() {
                tracing::warn!("the transaction's objects are unavailable, blind signing instead");
                return self.sign_transaction(transaction).await;
            }
            match self
                .sign_transaction_with_objects(transaction, &device_objects(transaction, objects))
                .await
            {
                Err(LedgerError::ClearSigningUnsupported(version)) => {
                    tracing::warn!("IOTA app {version} cannot clear-sign, blind signing instead");
                    self.sign_transaction(transaction).await
                }
                result => result,
            }
        }
    }

    /// The objects the IOTA app can use: the gas coins and immutable or owned
    /// inputs of `transaction`. The app finds each one it needs by hashing the
    /// objects in order, so any other object only slows it down.
    fn device_objects(transaction: &Transaction, objects: &[Object]) -> Vec<Object> {
        let Transaction::V1(transaction) = transaction else {
            unimplemented!("a new Transaction enum variant was added and needs to be handled")
        };
        let mut ids = transaction
            .gas_payment
            .objects
            .iter()
            .map(|reference| reference.object_id)
            .collect::<HashSet<_>>();
        if let TransactionKind::Programmable(programmable) = &transaction.kind {
            for input in &programmable.inputs {
                match input {
                    Input::ImmutableOrOwned(reference) => {
                        ids.insert(reference.object_id);
                    }
                    Input::Pure(_) | Input::Shared(_) | Input::Receiving(_) => {}
                    _ => {
                        unimplemented!("a new Input enum variant was added and needs to be handled")
                    }
                }
            }
        }
        objects
            .iter()
            .filter(|object| ids.contains(&object.id()))
            .cloned()
            .collect()
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    mod tests {
        use std::sync::{Arc, Mutex};

        use iota_ledger::{ApduAnswer, ApduCommand, Ledger, Transport, TransportFuture};
        use iota_types::{
            Ed25519PublicKey, MoveStruct, ObjectData, ObjectId, Owner, StructTag,
            TransactionDigest, Version,
        };

        use super::*;

        /// An IOTA plain transfer from the IOTA app's ragger tests.
        const TRANSACTION: &str = "00000100201b3669e321893ee49c387a08fc251dbfff37cd2a981e6c473a5b2afde19d363e010101000100000f58eb1351454d623a6a4366198d6cd5aa4a12a12a3caefb501476e06d8bd5b6011eec6c32ef36467331fb7b088b4acb1ce46f736354308e03ff6ce913a42734e2860000000000000020c7ebc6c4430b3cf7e58d75ab53ddb9180274def63b1ab5619fbdb7096cdbd7120f58eb1351454d623a6a4366198d6cd5aa4a12a12a3caefb501476e06d8bd5b6e80300000000000040420f000000000000";
        /// The gas coin of [`TRANSACTION`], from the same tests.
        const GAS_COIN: &str = "00018600000000000000281eec6c32ef36467331fb7b088b4acb1ce46f736354308e03ff6ce913a42734e2005ed0b200000000000f58eb1351454d623a6a4366198d6cd5aa4a12a12a3caefb501476e06d8bd5b620a7e7993dd298e10fb373fb708b9f9005be1963c6f074b202bbe7a7cf9d75d717b0f50e0000000000";

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
                            // The start request is a tag byte and one hash per
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

        async fn sign_parameters(
            version: [u8; 3],
            sign: impl AsyncFnOnce(LedgerSigner, Transaction, Object),
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
            let gas_coin = bcs::from_bytes(&hex_decode(GAS_COIN)).unwrap();
            sign(signer, transaction, gas_coin).await;
            sign_parameters.lock().unwrap().clone()
        }

        fn hex_decode(hex: &str) -> Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        }

        #[tokio::test]
        async fn blind_signs_without_objects() {
            let parameters = sign_parameters([1, 0, 1], async |signer, transaction, _| {
                signer.sign(&transaction).await.unwrap();
                signer.sign_with_objects(&transaction, &[]).await.unwrap();
            })
            .await;
            assert_eq!(parameters, [2, 2]);
        }

        #[tokio::test]
        async fn clear_signs_with_objects() {
            let parameters = sign_parameters([1, 0, 1], async |signer, transaction, gas_coin| {
                signer
                    .sign_with_objects(&transaction, &[gas_coin])
                    .await
                    .unwrap();
            })
            .await;
            assert_eq!(parameters, [3]);
        }

        #[tokio::test]
        async fn blind_signs_when_the_app_cannot_clear_sign() {
            let parameters = sign_parameters([0, 9, 2], async |signer, transaction, gas_coin| {
                signer
                    .sign_with_objects(&transaction, &[gas_coin])
                    .await
                    .unwrap();
            })
            .await;
            assert_eq!(parameters, [2]);
        }

        #[test]
        fn sends_the_device_only_the_objects_it_can_use() {
            let transaction = bcs::from_bytes(&hex_decode(TRANSACTION)).unwrap();
            let gas_coin: Object = bcs::from_bytes(&hex_decode(GAS_COIN)).unwrap();
            let contents = [&[5; ObjectId::LENGTH][..], &0u64.to_le_bytes()].concat();
            let shared = Object::new(
                ObjectData::Struct(
                    MoveStruct::new(
                        StructTag::new_gas_coin().into(),
                        Version::from_u64(1),
                        contents,
                    )
                    .unwrap(),
                ),
                Owner::Shared(Version::from_u64(1)),
                TransactionDigest::ZERO,
                0,
            );

            assert_eq!(
                device_objects(&transaction, &[shared, gas_coin.clone()]),
                [gas_coin]
            );
        }
    }
}

#[cfg(all(test, feature = "test-client"))]
mod tests {
    use std::sync::Mutex;

    use iota_types::{Address, Input, ObjectId, ObjectReference, SharedObjectReference, Version};

    use super::*;
    use crate::{RecordingClient, TestClient, TransactionBuilder, TransactionBuilderLedgerClient};

    /// Records the objects it is given and returns an arbitrary signature.
    #[derive(Default)]
    struct RecordingSigner {
        objects: Mutex<Option<Vec<Object>>>,
    }

    impl TransactionSigner for RecordingSigner {
        type Error = SignatureError;

        async fn sign(&self, _: &Transaction) -> Result<UserSignature, Self::Error> {
            unreachable!("the builder signs through `sign_with_objects`")
        }

        fn uses_objects(&self) -> bool {
            true
        }

        async fn sign_with_objects(
            &self,
            _: &Transaction,
            objects: &[Object],
        ) -> Result<UserSignature, Self::Error> {
            *self.objects.lock().unwrap() = Some(objects.to_vec());
            Err(SignatureError::from_source("recorded"))
        }
    }

    #[tokio::test]
    async fn execute_passes_the_objects_the_transaction_reads() {
        let coin = ObjectId::from_bytes([1; ObjectId::LENGTH]).unwrap();
        let mut builder = TransactionBuilder::new(Address::ZERO).with_client(TestClient);
        builder.transfer_objects(Address::new([2; Address::LENGTH]), [coin]);

        let signer = RecordingSigner::default();
        builder.execute(&signer, None).await.unwrap_err();

        // the selected gas coin and the transferred coin
        let objects = signer.objects.lock().unwrap().take().unwrap();
        let mut ids = objects.iter().map(Object::id).collect::<Vec<_>>();
        ids.sort();
        let gas_coin = ObjectId::from_bytes([0xee; ObjectId::LENGTH]).unwrap();
        assert_eq!(ids, [coin, gas_coin]);
    }

    #[tokio::test]
    async fn execute_fetches_objects_given_by_reference() {
        let coin = TestClient
            .object(ObjectId::from_bytes([1; ObjectId::LENGTH]).unwrap(), None)
            .await
            .unwrap()
            .unwrap();
        let reference: ObjectReference = coin.object_ref();
        let mut builder = TransactionBuilder::new(Address::ZERO).with_client(TestClient);
        builder.transfer_objects(Address::new([2; Address::LENGTH]), [reference]);

        let signer = RecordingSigner::default();
        builder.execute(&signer, None).await.unwrap_err();

        let objects = signer.objects.lock().unwrap().take().unwrap();
        assert!(
            objects
                .iter()
                .any(|object| object.object_ref() == reference)
        );
        assert_eq!(objects.len(), 2);
    }

    #[tokio::test]
    async fn execute_fails_without_signing_when_an_object_is_missing() {
        let coin = TestClient
            .object(ObjectId::from_bytes([1; ObjectId::LENGTH]).unwrap(), None)
            .await
            .unwrap()
            .unwrap();
        let client = RecordingClient {
            missing: vec![coin.id()],
            ..Default::default()
        };
        let mut builder = TransactionBuilder::new(Address::ZERO).with_client(client);
        builder.transfer_objects(Address::new([2; Address::LENGTH]), [coin.object_ref()]);

        let signer = RecordingSigner::default();
        let err = builder.execute(&signer, None).await.unwrap_err();

        assert!(signer.objects.lock().unwrap().is_none());
        assert!(
            err.to_string().contains(&coin.id().to_string()),
            "error should name the missing object, got: {err}"
        );
    }

    #[tokio::test]
    async fn execute_passes_shared_and_receiving_objects() {
        let coin = ObjectId::from_bytes([1; ObjectId::LENGTH]).unwrap();
        let receivable = ObjectId::from_bytes([3; ObjectId::LENGTH]).unwrap();
        let system_state = Input::Shared(SharedObjectReference {
            object_id: ObjectId::SYSTEM_STATE,
            initial_shared_version: Version::from_u64(1),
            mutable: false,
        });
        let mut builder = TransactionBuilder::new(Address::ZERO).with_client(TestClient);
        builder
            .move_call(Address::FRAMEWORK, "transfer", "public_receive")
            .arguments((
                coin,
                crate::Shared(ObjectId::CLOCK),
                system_state,
                crate::Receiving(receivable),
            ));

        let signer = RecordingSigner::default();
        builder.execute(&signer, None).await.unwrap_err();

        // the gas coin and every object input, including the system state
        // given by reference
        let objects = signer.objects.lock().unwrap().take().unwrap();
        let mut ids = objects.iter().map(Object::id).collect::<Vec<_>>();
        ids.sort();
        let gas_coin = ObjectId::from_bytes([0xee; ObjectId::LENGTH]).unwrap();
        let mut expected = [
            coin,
            receivable,
            gas_coin,
            ObjectId::CLOCK,
            ObjectId::SYSTEM_STATE,
        ];
        expected.sort();
        assert_eq!(ids, expected);
    }
}
