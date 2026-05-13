// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the Stardust migration package (`0x107a`).

/// Types from `0x107a::irc27`.
pub mod irc27 {
    use iota_types::Address;

    use crate::framework::url::Url;
    use crate::framework::vec_map::VecMap;
    use crate::std::fixed_point32::FixedPoint32;
    use crate::std::string::String as MoveString;

    /// Rust version of the Move `stardust::irc27::Irc27Metadata` type.
    ///
    /// The IRC27 NFT metadata standard schema.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Irc27Metadata {
        /// Version of the metadata standard.
        pub version: MoveString,
        /// The media type (MIME) of the asset.
        pub media_type: MoveString,
        /// URL pointing to the NFT file location.
        pub uri: Url,
        /// Alphanumeric text string defining the human identifiable name for
        /// the NFT.
        pub name: MoveString,
        /// The human-readable collection name of the NFT.
        pub collection_name: Option<MoveString>,
        /// Royalty payment addresses mapped to the payout percentage.
        pub royalties: VecMap<Address, FixedPoint32>,
        /// The human-readable name of the NFT creator.
        pub issuer_name: Option<MoveString>,
        /// The human-readable description of the NFT.
        pub description: Option<MoveString>,
        /// Additional attributes following [OpenSea metadata standards].
        ///
        /// [OpenSea metadata standards]: https://docs.opensea.io/docs/metadata-standards
        pub attributes: VecMap<MoveString, MoveString>,
        /// Legacy non-standard metadata fields.
        pub non_standard_fields: VecMap<MoveString, MoveString>,
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::vec_map::Entry;
        use crate::std::ascii;

        #[test]
        fn irc27_metadata_bcs_roundtrip() {
            let m = Irc27Metadata {
                version: MoveString::new(b"1.0".to_vec()),
                media_type: MoveString::new(b"image/png".to_vec()),
                uri: Url::new(ascii::String::new(b"https://iota.org/n.png".to_vec())),
                name: MoveString::new(b"name".to_vec()),
                collection_name: Some(MoveString::new(b"collection".to_vec())),
                royalties: VecMap::new(vec![Entry::new(
                    Address::new([0xab; 32]),
                    FixedPoint32::new(1_000),
                )]),
                issuer_name: None,
                description: None,
                attributes: VecMap::new(vec![Entry::new(
                    MoveString::new(b"k".to_vec()),
                    MoveString::new(b"v".to_vec()),
                )]),
                non_standard_fields: VecMap::default(),
            };
            let bytes = bcs::to_bytes(&m).unwrap();
            let decoded: Irc27Metadata = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(m, decoded);
        }
    }
}

/// Types from `0x107a::nft`.
pub mod nft {
    use iota_types::Address;

    use super::irc27::Irc27Metadata;
    use crate::framework::object::UID;

    /// Rust version of the Move `stardust::nft::NFT` type.
    ///
    /// One-time witness marker. The Move struct is empty; the Rust mirror
    /// carries a `dummy_field` to preserve the BCS wire format.
    #[allow(non_camel_case_types)]
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct NFT {
        dummy_field: bool,
    }

    /// Rust version of the Move `stardust::nft::Nft` type.
    ///
    /// The Stardust NFT representation.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Nft {
        /// The Nft's ID is inherited from Stardust.
        pub id: UID,
        /// Last sender address assigned before the migration. Not supported
        /// by the protocol after migration.
        pub legacy_sender: Option<Address>,
        /// The metadata feature.
        pub metadata: Option<Vec<u8>>,
        /// The tag feature.
        pub tag: Option<Vec<u8>>,
        /// The immutable issuer feature.
        pub immutable_issuer: Option<Address>,
        /// The immutable metadata feature.
        pub immutable_metadata: Irc27Metadata,
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn nft_marker_bcs_roundtrip() {
            let n = NFT::default();
            let bytes = bcs::to_bytes(&n).unwrap();
            assert_eq!(bytes, [0u8]);
            let decoded: NFT = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(n, decoded);
        }
    }
}

/// Types from `0x107a::nft_output`.
pub mod nft_output {
    use super::expiration_unlock_condition::ExpirationUnlockCondition;
    use super::storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition;
    use super::timelock_unlock_condition::TimelockUnlockCondition;
    use crate::framework::bag::Bag;
    use crate::framework::balance::Balance;
    use crate::framework::object::UID;

    /// Rust version of the Move `stardust::nft_output::NftOutput<T>` type.
    ///
    /// The Stardust NFT output representation.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct NftOutput<T> {
        /// A fresh UID — not the NFTID from Stardust.
        pub id: UID,
        /// The amount of coins held by the output.
        pub balance: Balance<T>,
        /// A `Bag` of native tokens keyed by stringified asset type.
        pub native_tokens: Bag,
        /// The storage deposit return unlock condition.
        pub storage_deposit_return_uc: Option<StorageDepositReturnUnlockCondition>,
        /// The timelock unlock condition.
        pub timelock_uc: Option<TimelockUnlockCondition>,
        /// The expiration unlock condition.
        pub expiration_uc: Option<ExpirationUnlockCondition>,
    }

    impl<T> NftOutput<T> {
        pub const fn new(
            id: UID,
            balance: Balance<T>,
            native_tokens: Bag,
            storage_deposit_return_uc: Option<StorageDepositReturnUnlockCondition>,
            timelock_uc: Option<TimelockUnlockCondition>,
            expiration_uc: Option<ExpirationUnlockCondition>,
        ) -> Self {
            Self {
                id,
                balance,
                native_tokens,
                storage_deposit_return_uc,
                timelock_uc,
                expiration_uc,
            }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::iota::IOTA;
        use iota_types::ObjectId;

        #[test]
        fn nft_output_bcs_roundtrip() {
            let o: NftOutput<IOTA> = NftOutput::new(
                UID::new(ObjectId::ZERO),
                Balance::new(1_000_000),
                Bag::new(UID::new(ObjectId::ZERO), 0),
                None,
                Some(TimelockUnlockCondition::new(1_700_000_000)),
                None,
            );
            let bytes = bcs::to_bytes(&o).unwrap();
            let decoded: NftOutput<IOTA> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(o, decoded);
        }
    }
}

/// Types from `0x107a::stardust_upgrade_label`.
pub mod stardust_upgrade_label {
    /// Rust version of the Move
    /// `stardust::stardust_upgrade_label::STARDUST_UPGRADE_LABEL` type.
    ///
    /// Name of the label applied to vested rewards migrated from Stardust.
    /// The Move struct is empty; the Rust mirror carries a `dummy_field`
    /// to preserve the BCS wire format.
    #[allow(non_camel_case_types)]
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct STARDUST_UPGRADE_LABEL {
        dummy_field: bool,
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn stardust_upgrade_label_bcs_roundtrip() {
            let l = STARDUST_UPGRADE_LABEL::default();
            let bytes = bcs::to_bytes(&l).unwrap();
            assert_eq!(bytes, [0u8]);
            let decoded: STARDUST_UPGRADE_LABEL = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(l, decoded);
        }
    }
}

/// Types from `0x107a::basic_output`.
pub mod basic_output {
    use iota_types::Address;

    use super::expiration_unlock_condition::ExpirationUnlockCondition;
    use super::storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition;
    use super::timelock_unlock_condition::TimelockUnlockCondition;
    use crate::framework::bag::Bag;
    use crate::framework::balance::Balance;
    use crate::framework::object::UID;

    /// Rust version of the Move `stardust::basic_output::BasicOutput<T>`
    /// type.
    ///
    /// A basic output that carries unlock conditions and feature flags. A
    /// basic output with an expiration unlock condition must be a shared
    /// object — that is the only way to handle the two possible addresses
    /// that can unlock the output. Note that the Move type has no `store`
    /// ability and no custom transfer function: callers either invoke
    /// `extract_assets` or call `receive` to obtain a `BasicOutput`.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct BasicOutput<T> {
        /// Hash of the `outputId` that was migrated.
        pub id: UID,
        /// The amount of coins held by the output.
        pub balance: Balance<T>,
        /// A `Bag` of native tokens keyed by stringified asset type.
        pub native_tokens: Bag,
        /// The storage deposit return unlock condition.
        pub storage_deposit_return_uc: Option<StorageDepositReturnUnlockCondition>,
        /// The timelock unlock condition.
        pub timelock_uc: Option<TimelockUnlockCondition>,
        /// The expiration unlock condition.
        pub expiration_uc: Option<ExpirationUnlockCondition>,
        /// The metadata feature.
        pub metadata: Option<Vec<u8>>,
        /// The tag feature.
        pub tag: Option<Vec<u8>>,
        /// The sender feature.
        pub sender: Option<Address>,
    }

    impl<T> BasicOutput<T> {
        #[allow(clippy::too_many_arguments)]
        pub const fn new(
            id: UID,
            balance: Balance<T>,
            native_tokens: Bag,
            storage_deposit_return_uc: Option<StorageDepositReturnUnlockCondition>,
            timelock_uc: Option<TimelockUnlockCondition>,
            expiration_uc: Option<ExpirationUnlockCondition>,
            metadata: Option<Vec<u8>>,
            tag: Option<Vec<u8>>,
            sender: Option<Address>,
        ) -> Self {
            Self {
                id,
                balance,
                native_tokens,
                storage_deposit_return_uc,
                timelock_uc,
                expiration_uc,
                metadata,
                tag,
                sender,
            }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::iota::IOTA;
        use iota_types::ObjectId;

        #[test]
        fn basic_output_bcs_roundtrip() {
            let o: BasicOutput<IOTA> = BasicOutput::new(
                UID::new(ObjectId::ZERO),
                Balance::new(1_000_000),
                Bag::new(UID::new(ObjectId::ZERO), 0),
                None,
                None,
                None,
                Some(b"metadata".to_vec()),
                Some(b"tag".to_vec()),
                Some(Address::new([0xab; 32])),
            );
            let bytes = bcs::to_bytes(&o).unwrap();
            let decoded: BasicOutput<IOTA> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(o, decoded);
        }
    }
}

/// Types from `0x107a::alias`.
pub mod alias {
    use iota_types::Address;

    use crate::framework::object::UID;

    /// Rust version of the Move `stardust::alias::Alias` type.
    ///
    /// The persisted Alias object from Stardust, without tokens or assets.
    /// Outputs owned by the AliasID/Address in Stardust will be sent to
    /// this object and have to be received via it once extracted from
    /// `AliasOutput`.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Alias {
        /// The ID of the Alias — hash of the Output ID that created the
        /// Alias Output in Stardust.
        pub id: UID,
        /// The last State Controller address assigned before the migration.
        pub legacy_state_controller: Address,
        /// A counter increased by 1 every time the alias was state-
        /// transitioned.
        pub state_index: u32,
        /// State metadata, used to store additional information.
        pub state_metadata: Option<Vec<u8>>,
        /// The sender feature.
        pub sender: Option<Address>,
        /// The metadata feature.
        pub metadata: Option<Vec<u8>>,
        /// The immutable issuer feature.
        pub immutable_issuer: Option<Address>,
        /// The immutable metadata feature.
        pub immutable_metadata: Option<Vec<u8>>,
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use iota_types::ObjectId;

        #[test]
        fn alias_bcs_roundtrip() {
            let a = Alias {
                id: UID::new(ObjectId::ZERO),
                legacy_state_controller: Address::new([0xab; 32]),
                state_index: 7,
                state_metadata: Some(b"state".to_vec()),
                sender: Some(Address::new([0xcd; 32])),
                metadata: None,
                immutable_issuer: None,
                immutable_metadata: None,
            };
            let bytes = bcs::to_bytes(&a).unwrap();
            let decoded: Alias = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(a, decoded);
        }
    }
}

/// Types from `0x107a::alias_output`.
pub mod alias_output {
    use crate::framework::bag::Bag;
    use crate::framework::balance::Balance;
    use crate::framework::object::UID;

    /// Rust version of the Move `stardust::alias_output::AliasOutput<T>`
    /// type.
    ///
    /// Owned object controlled by the Governor Address.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct AliasOutput<T> {
        /// A fresh UID — not the AliasID from Stardust.
        pub id: UID,
        /// The amount of coins held by the output.
        pub balance: Balance<T>,
        /// A `Bag` of native tokens keyed by stringified asset type.
        pub native_tokens: Bag,
    }

    impl<T> AliasOutput<T> {
        pub const fn new(id: UID, balance: Balance<T>, native_tokens: Bag) -> Self {
            Self {
                id,
                balance,
                native_tokens,
            }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::iota::IOTA;
        use iota_types::ObjectId;

        #[test]
        fn alias_output_bcs_roundtrip() {
            let o: AliasOutput<IOTA> = AliasOutput::new(
                UID::new(ObjectId::ZERO),
                Balance::new(5_000_000),
                Bag::new(UID::new(ObjectId::ZERO), 0),
            );
            let bytes = bcs::to_bytes(&o).unwrap();
            let decoded: AliasOutput<IOTA> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(o, decoded);
        }
    }
}

/// Types from `0x107a::timelock_unlock_condition`.
pub mod timelock_unlock_condition {
    /// Rust version of the Move
    /// `stardust::timelock_unlock_condition::TimelockUnlockCondition` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct TimelockUnlockCondition {
        /// Unix time (seconds since the Unix epoch) from which the output
        /// can be consumed.
        pub unix_time: u32,
    }

    impl TimelockUnlockCondition {
        pub const fn new(unix_time: u32) -> Self {
            Self { unix_time }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn timelock_unlock_condition_bcs_roundtrip() {
            let t = TimelockUnlockCondition::new(1_700_000_000);
            let bytes = bcs::to_bytes(&t).unwrap();
            let decoded: TimelockUnlockCondition = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(t, decoded);
        }
    }
}

/// Types from `0x107a::expiration_unlock_condition`.
pub mod expiration_unlock_condition {
    use iota_types::Address;

    /// Rust version of the Move
    /// `stardust::expiration_unlock_condition::ExpirationUnlockCondition`
    /// type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ExpirationUnlockCondition {
        /// The address that owns the output before `unix_time` is reached.
        pub owner: Address,
        /// The address allowed to spend the locked funds after `unix_time`.
        pub return_address: Address,
        /// Before this unix time, the address-unlock condition can unlock
        /// the output; after, only `return_address` can.
        pub unix_time: u32,
    }

    impl ExpirationUnlockCondition {
        pub const fn new(owner: Address, return_address: Address, unix_time: u32) -> Self {
            Self {
                owner,
                return_address,
                unix_time,
            }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn expiration_unlock_condition_bcs_roundtrip() {
            let e = ExpirationUnlockCondition::new(
                Address::new([0xab; 32]),
                Address::new([0xcd; 32]),
                1_700_000_000,
            );
            let bytes = bcs::to_bytes(&e).unwrap();
            let decoded: ExpirationUnlockCondition = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(e, decoded);
        }
    }
}

/// Types from `0x107a::storage_deposit_return_unlock_condition`.
pub mod storage_deposit_return_unlock_condition {
    use iota_types::Address;

    /// Rust version of the Move `stardust::storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition`
    /// type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct StorageDepositReturnUnlockCondition {
        /// The address to which the consuming transaction should deposit
        /// `return_amount`.
        pub return_address: Address,
        /// The amount of coins the consuming transaction should deposit to
        /// `return_address`.
        pub return_amount: u64,
    }

    impl StorageDepositReturnUnlockCondition {
        pub const fn new(return_address: Address, return_amount: u64) -> Self {
            Self {
                return_address,
                return_amount,
            }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn storage_deposit_return_unlock_condition_bcs_roundtrip() {
            let s = StorageDepositReturnUnlockCondition::new(Address::new([0xab; 32]), 12_345);
            let bytes = bcs::to_bytes(&s).unwrap();
            let decoded: StorageDepositReturnUnlockCondition = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(s, decoded);
        }
    }
}
