// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the Stardust migration package (`0x107a`).

use iota_types::Address;

use crate::{
    framework::{Bag, Balance, UID, Url, VecMap},
    std::FixedPoint32,
};

// ------------------------------------------------------------------
// basic_output
// ------------------------------------------------------------------

/// Rust version of the Move `stardust::basic_output::BasicOutput<T>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicOutput {
    /// Hash of the stardust `OutputId` that was migrated.
    pub id: UID,
    /// Coins held by the output.
    pub balance: Balance,
    /// Native tokens, keyed by the stringified type of the asset.
    pub native_tokens: Bag,
    pub storage_deposit_return: Option<StorageDepositReturnUnlockCondition>,
    pub timelock: Option<TimelockUnlockCondition>,
    pub expiration: Option<ExpirationUnlockCondition>,
    /// Stardust metadata feature; carried only until the object is consumed.
    pub metadata: Option<Vec<u8>>,
    /// Stardust tag feature; carried only until the object is consumed.
    pub tag: Option<Vec<u8>>,
    /// Stardust sender feature.
    pub sender: Option<Address>,
}

// ------------------------------------------------------------------
// expiration_unlock_condition
// ------------------------------------------------------------------

/// Rust version of the Move
/// `stardust::expiration_unlock_condition::ExpirationUnlockCondition` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExpirationUnlockCondition {
    /// Address that owns the output before `unix_time` has passed.
    pub owner: Address,
    /// Address that may spend the locked funds after `unix_time`.
    pub return_address: Address,
    /// Unix timestamp (seconds) at which the address-unlock right transfers
    /// from `owner` to `return_address`.
    pub unix_time: u32,
}

// ------------------------------------------------------------------
// irc27
// ------------------------------------------------------------------

/// Rust version of the Move `stardust::irc27::Irc27Metadata` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Irc27Metadata {
    /// Version of the metadata standard.
    pub version: String,
    /// Media type (MIME) of the asset.
    pub media_type: String,
    /// URL pointing to the NFT file location.
    pub uri: Url,
    /// Human-identifiable name for the NFT.
    pub name: String,
    /// Human-readable collection name of the NFT.
    pub collection_name: Option<String>,
    /// Royalty payment addresses mapped to their payout percentage.
    /// Note: keys are the legacy 32-byte hash of the BECH32-encoded address;
    /// royalty enforcement is not protocol-supported and is up to integrators.
    pub royalties: VecMap<Address, FixedPoint32>,
    /// Human-readable name of the NFT creator.
    pub issuer_name: Option<String>,
    /// Human-readable description of the NFT.
    pub description: Option<String>,
    /// Additional attributes following the OpenSea metadata standard.
    pub attributes: VecMap<String, String>,
    /// Legacy non-standard metadata fields.
    pub non_standard_fields: VecMap<String, String>,
}

// ------------------------------------------------------------------
// nft
// ------------------------------------------------------------------

/// Rust version of the Move `stardust::nft::Nft` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Nft {
    /// The NFT ID — the hash of the stardust `OutputId` that produced the
    /// migrated NFT output. Equivalent to the stardust `NftID`.
    pub id: UID,
    /// Last sender address assigned before the migration; not used after it.
    pub legacy_sender: Option<Address>,
    pub metadata: Option<Vec<u8>>,
    pub tag: Option<Vec<u8>>,
    pub immutable_issuer: Option<Address>,
    pub immutable_metadata: Irc27Metadata,
}

// ------------------------------------------------------------------
// nft_output
// ------------------------------------------------------------------

/// Rust version of the Move `stardust::nft_output::NftOutput<T>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NftOutput {
    /// A fresh UID — distinct from the stardust `NftID` that lives on
    /// the wrapped [`Nft`].
    pub id: UID,
    pub balance: Balance,
    pub native_tokens: Bag,
    pub storage_deposit_return: Option<StorageDepositReturnUnlockCondition>,
    pub timelock: Option<TimelockUnlockCondition>,
    pub expiration: Option<ExpirationUnlockCondition>,
}

// ------------------------------------------------------------------
// storage_deposit_return_unlock_condition
// ------------------------------------------------------------------

/// Rust version of the Move
/// `stardust::storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition`
/// type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StorageDepositReturnUnlockCondition {
    /// Address that the consuming transaction must pay `return_amount` to.
    pub return_address: Address,
    /// Amount of IOTA the consuming transaction must deposit at
    /// `return_address`.
    pub return_amount: u64,
}

// ------------------------------------------------------------------
// timelock_unlock_condition
// ------------------------------------------------------------------

/// Rust version of the Move
/// `stardust::timelock_unlock_condition::TimelockUnlockCondition` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimelockUnlockCondition {
    /// Unix timestamp (seconds) starting from which the output can be
    /// consumed.
    pub unix_time: u32,
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use iota_types::ObjectId;

    use super::*;

    fn sample_address(byte: u8) -> Address {
        Address::new([byte; Address::LENGTH])
    }

    fn sample_object_id(byte: u8) -> ObjectId {
        ObjectId::new([byte; ObjectId::LENGTH])
    }

    fn sample_url() -> Url {
        Url::try_from("https://iota.org/nft.png".to_owned()).unwrap()
    }

    fn dummy_irc27() -> Irc27Metadata {
        Irc27Metadata {
            version: "v1".to_owned(),
            media_type: "image/png".to_owned(),
            uri: sample_url(),
            name: "test".to_owned(),
            collection_name: Some("col".to_owned()),
            royalties: VecMap {
                contents: vec![crate::framework::Entry {
                    key: sample_address(0x01),
                    value: FixedPoint32 { value: 1 },
                }],
            },
            issuer_name: None,
            description: None,
            attributes: VecMap::default(),
            non_standard_fields: VecMap::default(),
        }
    }

    #[test]
    fn expiration_unlock_condition_bcs_roundtrip() {
        let cond = ExpirationUnlockCondition {
            owner: sample_address(0x01),
            return_address: sample_address(0x02),
            unix_time: 1_700_000_000,
        };
        let bytes = bcs::to_bytes(&cond).unwrap();
        let decoded: ExpirationUnlockCondition = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(cond, decoded);
    }

    #[test]
    fn storage_deposit_return_unlock_condition_bcs_roundtrip() {
        let cond = StorageDepositReturnUnlockCondition {
            return_address: sample_address(0x03),
            return_amount: 1_000_000,
        };
        let bytes = bcs::to_bytes(&cond).unwrap();
        let decoded: StorageDepositReturnUnlockCondition = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(cond, decoded);
    }

    #[test]
    fn timelock_unlock_condition_bcs_roundtrip() {
        let cond = TimelockUnlockCondition {
            unix_time: 1_700_000_000,
        };
        let bytes = bcs::to_bytes(&cond).unwrap();
        let decoded: TimelockUnlockCondition = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(cond, decoded);
    }

    #[test]
    fn basic_output_bcs_roundtrip() {
        let bo = BasicOutput {
            id: UID::new(sample_object_id(0xb0)),
            balance: Balance::new(1_000_000),
            native_tokens: Bag::default(),
            storage_deposit_return: Some(StorageDepositReturnUnlockCondition {
                return_address: sample_address(0x03),
                return_amount: 100,
            }),
            timelock: Some(TimelockUnlockCondition {
                unix_time: 1_700_000_000,
            }),
            expiration: None,
            metadata: Some(b"meta".to_vec()),
            tag: None,
            sender: Some(sample_address(0x04)),
        };
        let bytes = bcs::to_bytes(&bo).unwrap();
        let decoded: BasicOutput = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(bo, decoded);
    }

    #[test]
    fn irc27_metadata_bcs_roundtrip() {
        let m = dummy_irc27();
        let bytes = bcs::to_bytes(&m).unwrap();
        let decoded: Irc27Metadata = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn nft_bcs_roundtrip() {
        let nft = Nft {
            id: UID::new(sample_object_id(0xa0)),
            legacy_sender: Some(sample_address(0x05)),
            metadata: None,
            tag: Some(b"tag".to_vec()),
            immutable_issuer: Some(sample_address(0x06)),
            immutable_metadata: dummy_irc27(),
        };
        let bytes = bcs::to_bytes(&nft).unwrap();
        let decoded: Nft = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(nft, decoded);
    }

    #[test]
    fn nft_output_bcs_roundtrip() {
        let no = NftOutput {
            id: UID::new(sample_object_id(0xa1)),
            balance: Balance::new(2_000_000),
            native_tokens: Bag::default(),
            storage_deposit_return: None,
            timelock: None,
            expiration: Some(ExpirationUnlockCondition {
                owner: sample_address(0x01),
                return_address: sample_address(0x02),
                unix_time: 0,
            }),
        };
        let bytes = bcs::to_bytes(&no).unwrap();
        let decoded: NftOutput = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(no, decoded);
    }
}
