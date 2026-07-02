// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Address, Identifier, TypeParseError, TypeTag};

/// Type information for a move struct
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// struct-tag = address            ; address of the package
///              identifier         ; name of the module
///              identifier         ; name of the type
///              (vector type-tag)  ; type parameters
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct StructTag {
    pub(crate) address: Address,
    pub(crate) module: Identifier,
    pub(crate) name: Identifier,
    #[cfg_attr(feature = "proptest", strategy(proptest::strategy::Just(Vec::new())))]
    pub(crate) type_params: Vec<TypeTag>,
}

impl StructTag {
    pub fn new(
        address: impl Into<Address>,
        module: impl Into<Identifier>,
        name: impl Into<Identifier>,
        type_params: Vec<TypeTag>,
    ) -> Self {
        Self {
            address: address.into(),
            module: module.into(),
            name: name.into(),
            type_params,
        }
    }

    /// Returns whether the type (excluding the type params) is the same as
    /// another struct tag.
    pub fn is_same_type_as(&self, other: &StructTag) -> bool {
        self.address == other.address && self.module == other.module && self.name == other.name
    }

    /// Creates a new framework IOTA gas struct tag (`0x2::iota::IOTA`)
    pub fn new_gas() -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: Identifier::IOTA_MODULE,
            name: Identifier::IOTA,
            type_params: vec![],
        }
    }

    /// Checks if this is a framework IOTA gas type (`0x2::iota::IOTA`)
    pub fn is_gas(&self) -> bool {
        self.address == Address::FRAMEWORK
            && self.module == Identifier::IOTA_MODULE
            && self.name == Identifier::IOTA
            && self.type_params.is_empty()
    }

    /// Creates a new framework gas coin struct tag
    /// (`0x2::coin::Coin<0x2::iota::IOTA>`)
    pub fn new_gas_coin() -> Self {
        Self::new_coin(Self::new_gas())
    }

    /// Checks if this is a framework gas coin type
    /// (`0x2::coin::Coin<0x2::iota::IOTA>`)
    pub fn is_gas_coin(&self) -> bool {
        self.address == Address::FRAMEWORK
            && self.module == Identifier::COIN_MODULE
            && self.name == Identifier::COIN
            && matches!(
                self.type_params.as_slice(),
                [TypeTag::Struct(boxed_struct_tag)]
                if boxed_struct_tag.is_gas()
            )
    }

    /// Creates a new framework object ID struct tag (`0x2::object::ID`)
    pub fn new_id() -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: Identifier::OBJECT_MODULE,
            name: Identifier::ID,
            type_params: vec![],
        }
    }

    /// Checks if this is a framework object ID type (`0x2::object::ID`)
    pub fn is_id(&self) -> bool {
        self.address == Address::FRAMEWORK
            && self.module == Identifier::OBJECT_MODULE
            && self.name == Identifier::ID
            && self.type_params.is_empty()
    }

    /// Creates a new framework object UID struct tag (`0x2::object::UID`)
    pub fn new_uid() -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: Identifier::OBJECT_MODULE,
            name: Identifier::UID,
            type_params: vec![],
        }
    }

    /// Checks if this is a framework object UID type (`0x2::object::UID`)
    pub fn is_uid(&self) -> bool {
        self.address == Address::FRAMEWORK
            && self.module == Identifier::OBJECT_MODULE
            && self.name == Identifier::UID
            && self.type_params.is_empty()
    }

    /// Creates a new IOTA-Names [`Name`](crate::iota_names::Name) struct tag
    /// with the given package address.
    ///
    /// ```
    /// # use iota_sdk_types::{StructTag, iota_names::config::IotaNamesConfig};
    /// let iota_names_config = IotaNamesConfig::mainnet();
    /// let package_address = iota_names_config.package_address;
    /// assert_eq!(
    ///     StructTag::new_name(package_address).to_canonical_string(true),
    ///     format!("{package_address}::name::Name")
    /// );
    /// ```
    pub fn new_name(address: Address) -> Self {
        Self {
            address,
            module: Identifier::NAME_MODULE,
            name: Identifier::NAME,
            type_params: vec![],
        }
    }

    /// Checks if this is an IOTA-Names [`Name`](crate::iota_names::Name) type.
    /// Note that this does not check the package address, so it will return
    /// true for any struct with the correct module and type name with no
    /// type params.
    pub fn is_name(&self) -> bool {
        self.module == Identifier::NAME_MODULE
            && self.name == Identifier::NAME
            && self.type_params.is_empty()
    }

    /// Creates a new dynamic field struct tag
    /// (`0x2::dynamic_field::Field<KeyType, ValueType>`)
    pub fn new_dynamic_field(key: impl Into<TypeTag>, value: impl Into<TypeTag>) -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: Identifier::DYNAMIC_FIELD_MODULE,
            name: Identifier::FIELD,
            type_params: vec![key.into(), value.into()],
        }
    }

    /// Checks if this is a Dynamic Field type
    /// (`0x2::dynamic_field::Field<KeyType, ValueType>`)
    pub fn is_dynamic_field(&self) -> bool {
        self.address == Address::FRAMEWORK
            && self.module == Identifier::DYNAMIC_FIELD_MODULE
            && self.name == Identifier::FIELD
            && self.type_params.len() == 2
    }

    /// Returns the coin type if this is a Coin type, None otherwise
    pub fn coin_type_opt(&self) -> Option<&crate::TypeTag> {
        if self.is_coin() {
            self.type_params.first()
        } else {
            None
        }
    }

    /// Returns the coin type of this `StructTag`, panics if not a coin
    pub fn coin_type(&self) -> &TypeTag {
        self.coin_type_opt().expect("not a coin")
    }

    /// Returns the address part of a `StructTag`
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the module part of a `StructTag`
    pub fn module(&self) -> &Identifier {
        &self.module
    }

    /// Returns the name part of a `StructTag`
    pub fn name(&self) -> &Identifier {
        &self.name
    }

    /// Returns the type params part of a `StructTag`
    pub fn type_params(&self) -> &[TypeTag] {
        &self.type_params
    }

    /// Returns a mutable reference to the type params part of a `StructTag`
    pub fn type_params_mut(&mut self) -> &mut Vec<TypeTag> {
        &mut self.type_params
    }

    /// Decomposes the StructTag into its parts
    pub fn into_parts(self) -> (Address, Identifier, Identifier, Vec<TypeTag>) {
        (self.address, self.module, self.name, self.type_params)
    }

    /// Checks if this is a timelocked coin balance `TimeLock<Balance<T>>`
    pub fn is_timelocked_balance(&self) -> bool {
        self.is_time_lock()
            && matches!(
                self.type_params.as_slice(),
                [TypeTag::Struct(inner)] if inner.is_balance()
            )
    }

    /// Checks if this is an IOTA balance type
    /// (`0x2::balance::Balance<0x2::iota::IOTA>`)
    pub fn is_gas_balance(&self) -> bool {
        self.is_balance()
            && matches!(
                self.type_params.as_slice(),
                [TypeTag::Struct(inner)] if inner.is_gas()
            )
    }

    /// Creates a new timelocked IOTA balance struct tag
    /// (`0x2::timelock::TimeLock<0x2::balance::Balance<0x2::iota::IOTA>>`)
    pub fn new_timelocked_gas_balance() -> Self {
        Self::new_time_lock(Self::new_balance(Self::new_gas()))
    }

    /// Checks if this is a timelocked IOTA balance type
    /// (`0x2::timelock::TimeLock<0x2::balance::Balance<0x2::iota::IOTA>>`)
    pub fn is_timelocked_gas_balance(&self) -> bool {
        self.is_time_lock()
            && matches!(
                self.type_params.as_slice(),
                [TypeTag::Struct(inner)] if inner.is_gas_balance()
            )
    }

    /// Returns the string representation of this struct tag using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        let mut tag = format!(
            "{}::{}::{}",
            self.address.to_canonical_string(with_prefix),
            self.module,
            self.name
        );
        if let Some(first_type) = self.type_params.first() {
            tag.push_str(&format!("<{}", first_type.to_canonical_string(with_prefix)));
            for ty in self.type_params.iter().skip(1) {
                tag.push_str(&format!(",{}", ty.to_canonical_string(with_prefix)));
            }
            tag.push('>');
        }
        tag
    }
}

macro_rules! add_struct_tag_ctor {
    (@with_module $address:ident, $($module:ident :: $name:ident),+ $(,)?) => {
        $(
            paste::paste! {
                pub fn [< new_ $module:snake _ $name:snake >]() -> Self {
                    Self {
                        address: Address::$address,
                        module: Identifier::from_static(stringify!($module)),
                        name: Identifier::from_static(stringify!($name)),
                        type_params: vec![],
                    }
                }

                pub fn [< is_ $module:snake _ $name:snake >](&self) -> bool {
                    self.address == Address::$address
                        && self.module == Identifier::from_static(stringify!($module))
                        && self.name == Identifier::from_static(stringify!($name))
                        && self.type_params.is_empty()
                }
            }
        )+
    };
    ($address:ident, $($module:ident :: $name:ident),+ $(,)?) => {
        $(
            paste::paste! {
                pub fn [< new_ $name:snake >]() -> Self {
                    Self {
                        address: Address::$address,
                        module: Identifier::from_static(stringify!($module)),
                        name: Identifier::from_static(stringify!($name)),
                        type_params: vec![],
                    }
                }

                pub fn [< is_ $name:snake >](&self) -> bool {
                    self.address == Address::$address
                        && self.module == Identifier::from_static(stringify!($module))
                        && self.name == Identifier::from_static(stringify!($name))
                        && self.type_params.is_empty()
                }
            }
        )+
    };
}

macro_rules! add_struct_tag_ctor_from_struct_tag {
    (@with_module $address:ident, $($module:ident :: $name:ident),+ $(,)?) => {
        $(
            paste::paste! {
                pub fn [< new_ $module:snake _ $name:snake >](struct_tag: impl Into<StructTag>) -> Self {
                    Self {
                        address: Address::$address,
                        module: Identifier::from_static(stringify!($module)),
                        name: Identifier::from_static(stringify!($name)),
                        type_params: vec![TypeTag::Struct(Box::new(struct_tag.into()))],
                    }
                }

                pub fn [< is_ $module:snake _ $name:snake >](&self) -> bool {
                    self.address == Address::$address
                        && self.module == Identifier::from_static(stringify!($module))
                        && self.name == Identifier::from_static(stringify!($name))
                        && self.type_params.len() == 1
                }
            }
        )+
    };
    ($address:ident, $($module:ident :: $name:ident),+ $(,)?) => {
        $(
            paste::paste! {
                pub fn [< new_ $name:snake >](struct_tag: impl Into<StructTag>) -> Self {
                    Self {
                        address: Address::$address,
                        module: Identifier::from_static(stringify!($module)),
                        name: Identifier::from_static(stringify!($name)),
                        type_params: vec![TypeTag::Struct(Box::new(struct_tag.into()))],
                    }
                }

                pub fn [< is_ $name:snake >](&self) -> bool {
                    self.address == Address::$address
                        && self.module == Identifier::from_static(stringify!($module))
                        && self.name == Identifier::from_static(stringify!($name))
                        && self.type_params.len() == 1
                }
            }
        )+
    };
}

macro_rules! add_struct_tag_ctor_from_type_tag {
    (@with_module $address:ident, $($module:ident :: $name:ident),+ $(,)?) => {
        $(
            paste::paste! {
                pub fn [< new_ $module:snake _ $name:snake >](type_tag: impl Into<TypeTag>) -> Self {
                    Self {
                        address: Address::$address,
                        module: Identifier::from_static(stringify!($module)),
                        name: Identifier::from_static(stringify!($name)),
                        type_params: vec![type_tag.into()],
                    }
                }

                pub fn [< is_ $module:snake _ $name:snake >](&self) -> bool {
                    self.address == Address::$address
                        && self.module == Identifier::from_static(stringify!($module))
                        && self.name == Identifier::from_static(stringify!($name))
                        && self.type_params.len() == 1
                }
            }
        )+
    };
    ($address:ident, $($module:ident :: $name:ident),+ $(,)?) => {
        $(
            paste::paste! {
                pub fn [< new_ $name:snake >](type_tag: impl Into<TypeTag>) -> Self {
                    Self {
                        address: Address::$address,
                        module: Identifier::from_static(stringify!($module)),
                        name: Identifier::from_static(stringify!($name)),
                        type_params: vec![type_tag.into()],
                    }
                }

                pub fn [< is_ $name:snake >](&self) -> bool {
                    self.address == Address::$address
                        && self.module == Identifier::from_static(stringify!($module))
                        && self.name == Identifier::from_static(stringify!($name))
                        && self.type_params.len() == 1
                }
            }
        )+
    };
}

impl StructTag {
    add_struct_tag_ctor!(
        FRAMEWORK,
        authenticator_state::AuthenticatorState,
        clock::Clock,
        iota::IotaTreasuryCap,
        kiosk::Kiosk,
        kiosk::KioskOwnerCap,
        package::Publisher,
        package::UpgradeCap,
        package::UpgradeTicket,
        package::UpgradeReceipt,
        random::Random,
        system_admin_cap::IotaSystemAdminCap,
        url::Url,
        bag::Bag,
        object_bag::ObjectBag,
        tx_context::TxContext,
        deny_list::DenyList,
        zklogin_verified_issuer::VerifiedIssuer,
        package_metadata::PackageMetadataV1
    );
    add_struct_tag_ctor!(@with_module FRAMEWORK, deny_list::ConfigKey, deny_list::AddressKey, deny_list::GlobalPauseKey);
    add_struct_tag_ctor!(
        SYSTEM,
        iota_system::IotaSystemState,
        staking_pool::StakedIota,
        timelocked_staking::TimelockedStakedIota,
        iota_system_state_inner::SystemEpochInfoEvent,
        validator_cap::UnverifiedValidatorOperationCap
    );
    add_struct_tag_ctor!(STD, string::String);
    add_struct_tag_ctor!(@with_module STD, ascii::String);
    add_struct_tag_ctor_from_struct_tag!(
        FRAMEWORK,
        coin::CoinMetadata,
        coin::TreasuryCap,
        coin_manager::CoinManager,
        display::DisplayCreated
    );
    add_struct_tag_ctor_from_struct_tag!(@with_module FRAMEWORK, display::VersionUpdated);
    add_struct_tag_ctor_from_type_tag!(
        FRAMEWORK,
        coin::Coin,
        coin::RegulatedCoinMetadata,
        coin::DenyCapV1,
        balance::Balance,
        timelock::TimeLock,
        config::Config,
        display::Display,
        coin_manager::CoinManagerTreasuryCap,
        coin_manager::CoinManagerMetadataCap,
        token::Token,
        token::TokenPolicyCap,
        token::TokenPolicy,
        transfer_policy::TransferPolicy,
        transfer_policy::TransferPolicyCap,
        labeler::LabelerCap,
        kiosk::PurchaseCap,
    );
    add_struct_tag_ctor_from_type_tag!(@with_module FRAMEWORK, config::Setting, dynamic_object_field::Wrapper, transfer::Receiving);
    add_struct_tag_ctor_from_type_tag!(STD, option::Option);
    add_struct_tag_ctor!(STARDUST, alias::Alias, nft::Nft, irc27::Irc27Metadata);
    add_struct_tag_ctor_from_type_tag!(
        STARDUST,
        basic_output::BasicOutput,
        nft_output::NftOutput,
        alias_output::AliasOutput,
    );

    /// Creates a new zkLogin verified ID struct tag
    /// (`0x2::zklogin_verified_id::VerifiedID`).
    ///
    /// Hand-written because the `ID` acronym does not round-trip through the
    /// macro's snake-case conversion (it would yield `verified_i_d`), the
    /// same reason [`StructTag::new_id`] is hand-written.
    pub fn new_verified_id() -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: Identifier::from_static("zklogin_verified_id"),
            name: Identifier::from_static("VerifiedID"),
            type_params: vec![],
        }
    }

    /// Checks if this is a zkLogin verified ID type
    /// (`0x2::zklogin_verified_id::VerifiedID`).
    pub fn is_verified_id(&self) -> bool {
        self.address == Address::FRAMEWORK
            && self.module == Identifier::from_static("zklogin_verified_id")
            && self.name == Identifier::from_static("VerifiedID")
            && self.type_params.is_empty()
    }
}

impl std::fmt::Display for StructTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}::{}::{}",
            self.address.to_short_hex(),
            self.module,
            self.name
        )?;
        if let Some(first_type) = self.type_params.first() {
            write!(f, "<{first_type}")?;
            for ty in self.type_params.iter().skip(1) {
                write!(f, ", {ty}")?;
            }
            write!(f, ">")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for StructTag {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use winnow::Parser;
        crate::move_core::parse::parse_struct_tag
            .parse(s)
            .map_err(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_tag_parsing() {
        let tag_str = "0x2::coin::Coin<0x2::iota::IOTA>";
        let struct_tag: StructTag = tag_str.parse().unwrap();
        assert!(struct_tag.is_coin());
        let coin_type = struct_tag.coin_type();
        assert!(coin_type.is_struct());
        let coin_struct = coin_type.as_struct_tag();
        assert!(coin_struct.is_gas());
    }

    /// `is_*` predicates for non-generic types (generated by
    /// `add_struct_tag_ctor!`) require `type_params` to be empty. A tag
    /// with bogus type params for a non-generic type must not match.
    #[test]
    fn is_predicate_rejects_type_params_on_non_generic_type() {
        let ok: StructTag = "0x2::package::UpgradeCap".parse().unwrap();
        let bogus: StructTag = "0x2::package::UpgradeCap<u64>".parse().unwrap();
        assert!(ok.is_upgrade_cap());
        assert!(!bogus.is_upgrade_cap());

        let clock_ok: StructTag = "0x2::clock::Clock".parse().unwrap();
        let clock_bogus: StructTag = "0x2::clock::Clock<u64>".parse().unwrap();
        assert!(clock_ok.is_clock());
        assert!(!clock_bogus.is_clock());
    }

    /// `is_*` predicates for single-generic types (generated by
    /// `add_struct_tag_ctor_from_type_tag!`) require exactly one type
    /// parameter — they must reject empty and over-parameterized tags.
    #[test]
    fn is_predicate_requires_arity_one_on_generic_type() {
        let coin_t = TypeTag::Struct(Box::new(StructTag::new_gas()));

        // config::Config<phantom WriteCap>
        let cfg_ok = StructTag::new_config(coin_t.clone());
        let cfg_no_params: StructTag = "0x2::config::Config".parse().unwrap();
        assert!(cfg_ok.is_config());
        assert!(!cfg_no_params.is_config());

        // coin::RegulatedCoinMetadata<phantom T>
        let rcm_ok = StructTag::new_regulated_coin_metadata(coin_t.clone());
        let rcm_no_params: StructTag = "0x2::coin::RegulatedCoinMetadata".parse().unwrap();
        assert!(rcm_ok.is_regulated_coin_metadata());
        assert!(!rcm_no_params.is_regulated_coin_metadata());

        // coin::DenyCapV1<phantom T>
        let dcap_ok = StructTag::new_deny_cap_v1(coin_t.clone());
        let dcap_no_params: StructTag = "0x2::coin::DenyCapV1".parse().unwrap();
        assert!(dcap_ok.is_deny_cap_v1());
        assert!(!dcap_no_params.is_deny_cap_v1());

        // transfer::Receiving<phantom T: key>
        let recv_ok = StructTag::new_transfer_receiving(coin_t);
        let recv_no_params: StructTag = "0x2::transfer::Receiving".parse().unwrap();
        assert!(recv_ok.is_transfer_receiving());
        assert!(!recv_no_params.is_transfer_receiving());
    }

    /// The generic constructors fill in `type_params` with the supplied
    /// inner type — they don't produce no-generic placeholder tags.
    #[test]
    fn generic_ctor_fills_in_type_param() {
        let inner = TypeTag::Struct(Box::new(StructTag::new_gas()));
        let tag = StructTag::new_transfer_receiving(inner.clone());
        assert_eq!(tag.type_params(), &[inner]);
    }
}
