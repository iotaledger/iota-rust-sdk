// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Address, Identifier, ObjectId, StructTag};

/// Events emitted during the successful execution of a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-events = vector event
/// ```
#[derive(Eq, PartialEq, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct TransactionEvents(pub Vec<Event>);

/// An event
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// event = object-id identifier address struct-tag bytes
/// ```
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Event {
    /// Package id of the top-level function invoked by a MoveCall command which
    /// triggered this event to be emitted.
    pub package_id: ObjectId,
    /// Module name of the top-level function invoked by a MoveCall command
    /// which triggered this event to be emitted.
    pub module: Identifier,
    /// Address of the account that sent the transaction where this event was
    /// emitted.
    pub sender: Address,
    /// The type of the event emitted
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub type_: StructTag,
    /// BCS serialized bytes of the event
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::ReadableBase64Encoded")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base64"))]
    pub contents: Vec<u8>,
}

fn is_system_epoch_info_event_type(type_: &StructTag, name: &str) -> bool {
    type_.address() == Address::SYSTEM
        && type_.module().as_str() == "iota_system_state_inner"
        && type_.name().as_str() == name
}

impl Event {
    pub fn is_system_epoch_info_event(&self) -> bool {
        self.is_system_epoch_info_event_v1() || self.is_system_epoch_info_event_v2()
    }

    pub fn is_system_epoch_info_event_v1(&self) -> bool {
        is_system_epoch_info_event_type(&self.type_, "SystemEpochInfoEventV1")
    }

    pub fn is_system_epoch_info_event_v2(&self) -> bool {
        is_system_epoch_info_event_type(&self.type_, "SystemEpochInfoEventV2")
    }

    /// Generate a random event for testing purposes.
    ///
    /// This method creates events with structured randomness:
    /// - Identifiers (module, type module, type name) are generated as strings
    ///   like "mod1234" starting with a letter.
    /// - Type parameters are randomly selected from simple types (U8, U16,
    ///   etc.) with 0-3 parameters.
    /// - Contents are random bytes with length 0-32.
    /// - Other fields (package_id, sender, type address) use their respective
    ///   random methods.
    ///
    /// This is not fully random but designed to produce valid, varied test
    /// data.
    #[cfg(all(feature = "rand", not(target_arch = "wasm32")))]
    #[cfg_attr(doc_cfg, doc(cfg(all(feature = "rand", not(target_arch = "wasm32")))))]
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};

        let mut rng = OsRng;

        let module_str = format!("mod{}", rng.next_u32() % 10000);
        let type_module_str = format!("type_mod{}", rng.next_u32() % 10000);
        let type_name_str = format!("type_name{}", rng.next_u32() % 10000);

        let contents_len = rng.next_u32() % 33; // 0 to 32
        let mut contents = vec![0u8; contents_len as usize];
        rng.fill_bytes(&mut contents);

        let num_type_params = rng.next_u32() % 4; // 0 to 3
        let type_params = (0..num_type_params)
            .map(|_| match rng.next_u32() % 9 {
                0 => TypeTag::U8,
                1 => TypeTag::U16,
                2 => TypeTag::U32,
                3 => TypeTag::U64,
                4 => TypeTag::U128,
                5 => TypeTag::U256,
                6 => TypeTag::Bool,
                7 => TypeTag::Address,
                8 => TypeTag::Signer,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();

        Self {
            package_id: ObjectId::random(),
            module: Identifier::new(&module_str).unwrap(),
            sender: Address::random(),
            type_: StructTag::new(
                Address::random(),
                Identifier::new(&type_module_str).unwrap(),
                Identifier::new(&type_name_str).unwrap(),
                type_params,
            ),
            contents,
        }
    }
}

#[cfg(test)]
#[cfg(all(feature = "rand", not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn test_event_random() {
        for _ in 0..100 {
            let event = Event::random();
            // Just check that it creates something
            assert!(!event.module.as_str().is_empty());
            assert!(!event.type_.module().as_str().is_empty());
            assert!(!event.type_.name().as_str().is_empty());
        }
    }
}
