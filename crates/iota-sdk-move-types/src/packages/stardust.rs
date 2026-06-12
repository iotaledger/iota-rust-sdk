// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the Stardust migration package (`0x107a`).

/// Types from `0x107a::irc27`.
pub mod irc27 {
    use iota_types::Address;

    use crate::{
        framework::{url::Url, vec_map::VecMap},
        std::{fixed_point32::FixedPoint32, string},
    };

    /// Rust version of the Move `stardust::irc27::Irc27Metadata` type.
    ///
    /// The IRC27 NFT metadata standard schema.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Irc27Metadata {
        /// Version of the metadata standard.
        pub version: string::String,
        /// The media type (MIME) of the asset.
        pub media_type: string::String,
        /// URL pointing to the NFT file location.
        pub uri: Url,
        /// Alphanumeric text string defining the human identifiable name for
        /// the NFT.
        pub name: string::String,
        /// The human-readable collection name of the NFT.
        pub collection_name: Option<string::String>,
        /// Royalty payment addresses mapped to the payout percentage.
        pub royalties: VecMap<Address, FixedPoint32>,
        /// The human-readable name of the NFT creator.
        pub issuer_name: Option<string::String>,
        /// The human-readable description of the NFT.
        pub description: Option<string::String>,
        /// Additional attributes following [OpenSea metadata standards].
        ///
        /// [OpenSea metadata standards]: https://docs.opensea.io/docs/metadata-standards
        pub attributes: VecMap<string::String, string::String>,
        /// Legacy non-standard metadata fields.
        pub non_standard_fields: VecMap<string::String, string::String>,
    }

    #[cfg(feature = "serde")]
    impl Irc27Metadata {
        /// Decode an [`Irc27Metadata`] from BCS bytes without verifying any
        /// on-chain type tag (the metadata is usually nested inside an
        /// [`Nft`](super::nft::Nft), not stored as a top-level object).
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
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
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct NFT {
        dummy_field: bool,
    }

    /// Rust version of the Move `stardust::nft::Nft` type.
    ///
    /// The Stardust NFT representation.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
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

    #[cfg(feature = "serde")]
    impl Nft {
        /// Decode an [`Nft`] from BCS bytes without verifying the on-chain
        /// type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode an [`Nft`] from an on-chain object, validating that the
        /// object's type tag matches `0x107a::nft::Nft`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            if !move_struct.object_type().is_nft() {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }
}

/// Types from `0x107a::nft_output`.
pub mod nft_output {
    use super::{
        expiration_unlock_condition::ExpirationUnlockCondition,
        storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition,
        timelock_unlock_condition::TimelockUnlockCondition,
    };
    use crate::framework::{bag::Bag, balance::Balance, object::UID};

    /// Rust version of the Move `stardust::nft_output::NftOutput<T>` type.
    ///
    /// The Stardust NFT output representation.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
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

    #[cfg(feature = "serde")]
    impl<T> NftOutput<T>
    where
        T: serde::de::DeserializeOwned,
    {
        /// Decode a [`NftOutput<T>`] from BCS bytes without verifying the
        /// on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`NftOutput<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x107a::nft_output::NftOutput<coin_type>`.
        ///
        /// Escape hatch for coin types only known at runtime; nothing ties
        /// `coin_type` to `T`. When the coin type is known at compile time,
        /// prefer [`Self::try_from_object`].
        pub fn try_from_object_with_type(
            object: &iota_types::Object,
            coin_type: &iota_types::TypeTag,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            let tag = move_struct.struct_tag();
            if !tag.is_nft_output() || tag.type_params() != core::slice::from_ref(coin_type) {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    #[cfg(feature = "serde")]
    impl<T> NftOutput<T>
    where
        T: serde::de::DeserializeOwned + crate::MoveType,
    {
        /// Decode a [`NftOutput<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x107a::nft_output::NftOutput<T>`, including the coin marker
        /// `T`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            Self::try_from_object_with_type(object, &T::type_tag())
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
    #[expect(non_camel_case_types)]
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct STARDUST_UPGRADE_LABEL {
        dummy_field: bool,
    }
}

/// Types from `0x107a::basic_output`.
pub mod basic_output {
    use iota_types::Address;

    use super::{
        expiration_unlock_condition::ExpirationUnlockCondition,
        storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition,
        timelock_unlock_condition::TimelockUnlockCondition,
    };
    use crate::framework::{bag::Bag, balance::Balance, object::UID};

    /// Rust version of the Move `stardust::basic_output::BasicOutput<T>`
    /// type.
    ///
    /// A basic output that carries unlock conditions and feature flags. A
    /// basic output with an expiration unlock condition must be a shared
    /// object — that is the only way to handle the two possible addresses
    /// that can unlock the output. Note that the Move type has no `store`
    /// ability and no custom transfer function: callers either invoke
    /// `extract_assets` or call `receive` to obtain a `BasicOutput`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
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
        #[expect(clippy::too_many_arguments)]
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

    #[cfg(feature = "serde")]
    impl<T> BasicOutput<T>
    where
        T: serde::de::DeserializeOwned,
    {
        /// Decode a [`BasicOutput<T>`] from BCS bytes without verifying
        /// the on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`BasicOutput<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x107a::basic_output::BasicOutput<coin_type>`.
        ///
        /// Escape hatch for coin types only known at runtime; nothing ties
        /// `coin_type` to `T`. When the coin type is known at compile time,
        /// prefer [`Self::try_from_object`].
        pub fn try_from_object_with_type(
            object: &iota_types::Object,
            coin_type: &iota_types::TypeTag,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            let tag = move_struct.struct_tag();
            if !tag.is_basic_output() || tag.type_params() != core::slice::from_ref(coin_type) {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    #[cfg(feature = "serde")]
    impl<T> BasicOutput<T>
    where
        T: serde::de::DeserializeOwned + crate::MoveType,
    {
        /// Decode a [`BasicOutput<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x107a::basic_output::BasicOutput<T>`, including the coin
        /// marker `T`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            Self::try_from_object_with_type(object, &T::type_tag())
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
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
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

    #[cfg(feature = "serde")]
    impl Alias {
        /// Decode an [`Alias`] from BCS bytes without verifying the on-chain
        /// type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode an [`Alias`] from an on-chain object, validating that the
        /// object's type tag matches `0x107a::alias::Alias`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            if !move_struct.object_type().is_alias() {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }
}

/// Types from `0x107a::alias_output`.
pub mod alias_output {
    use crate::framework::{bag::Bag, balance::Balance, object::UID};

    /// Rust version of the Move `stardust::alias_output::AliasOutput<T>`
    /// type.
    ///
    /// Owned object controlled by the Governor Address.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
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

    #[cfg(feature = "serde")]
    impl<T> AliasOutput<T>
    where
        T: serde::de::DeserializeOwned,
    {
        /// Decode an [`AliasOutput<T>`] from BCS bytes without verifying
        /// the on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode an [`AliasOutput<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x107a::alias_output::AliasOutput<coin_type>`.
        ///
        /// Escape hatch for coin types only known at runtime; nothing ties
        /// `coin_type` to `T`. When the coin type is known at compile time,
        /// prefer [`Self::try_from_object`].
        pub fn try_from_object_with_type(
            object: &iota_types::Object,
            coin_type: &iota_types::TypeTag,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            let tag = move_struct.struct_tag();
            if !tag.is_alias_output() || tag.type_params() != core::slice::from_ref(coin_type) {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    #[cfg(feature = "serde")]
    impl<T> AliasOutput<T>
    where
        T: serde::de::DeserializeOwned + crate::MoveType,
    {
        /// Decode an [`AliasOutput<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x107a::alias_output::AliasOutput<T>`, including the coin
        /// marker `T`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            Self::try_from_object_with_type(object, &T::type_tag())
        }
    }
}

/// Types from `0x107a::timelock_unlock_condition`.
pub mod timelock_unlock_condition {
    /// Rust version of the Move
    /// `stardust::timelock_unlock_condition::TimelockUnlockCondition` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
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
}

/// Types from `0x107a::expiration_unlock_condition`.
pub mod expiration_unlock_condition {
    use iota_types::Address;

    /// Rust version of the Move
    /// `stardust::expiration_unlock_condition::ExpirationUnlockCondition`
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
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
}

/// Types from `0x107a::storage_deposit_return_unlock_condition`.
pub mod storage_deposit_return_unlock_condition {
    use iota_types::Address;

    /// Rust version of the Move
    /// `stardust::storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition`
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
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
}
