// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ValidatorCommitteeMember(pub iota_types::ValidatorCommitteeMember);

#[uniffi::export]
impl ValidatorCommitteeMember {
    pub fn public_key(&self) -> Bls12381PublicKey {
        self.0.public_key.into()
    }

    pub fn stake(&self) -> u64 {
        self.0.stake
    }
}

macro_rules! impl_public_key {
    ($t:ident) => {
        #[derive(Clone, Debug, derive_more::From, uniffi::Object)]
        pub struct $t(pub iota_types::$t);

        #[uniffi::export]
        impl $t {
            #[uniffi::constructor]
            pub fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
                Ok(Self(iota_types::$t::from_bytes(bytes)?))
            }

            #[uniffi::constructor]
            pub fn from_str(s: &str) -> anyhow::Result<Self> {
                Ok(Self(std::str::FromStr::from_str(s)?))
            }

            #[uniffi::constructor]
            pub fn generate() -> Self {
                let mut rng = rand::thread_rng();
                Self(iota_types::$t::generate(&mut rng))
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.as_bytes().to_vec()
            }
        }
    };
}

impl_public_key!(Bls12381PublicKey);
impl_public_key!(Ed25519PublicKey);
impl_public_key!(Secp256k1PublicKey);
impl_public_key!(Secp256r1PublicKey);
