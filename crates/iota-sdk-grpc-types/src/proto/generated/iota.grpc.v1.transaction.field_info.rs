// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod _field_impls {
    #![allow(clippy::wrong_self_convention)]
    use super::*;
    use crate::field::MessageFields;
    use crate::field::MessageField;
    #[allow(unused_imports)]
    use crate::v1::bcs::BcsData;
    #[allow(unused_imports)]
    use crate::v1::bcs::BcsDataFieldPathBuilder;
    #[allow(unused_imports)]
    use crate::v1::event::Event;
    #[allow(unused_imports)]
    use crate::v1::event::EventFieldPathBuilder;
    #[allow(unused_imports)]
    use crate::v1::object::Object;
    #[allow(unused_imports)]
    use crate::v1::object::ObjectFieldPathBuilder;
    #[allow(unused_imports)]
    use crate::v1::signatures::UserSignature;
    #[allow(unused_imports)]
    use crate::v1::signatures::UserSignatureFieldPathBuilder;
    #[allow(unused_imports)]
    use crate::v1::types::Address;
    #[allow(unused_imports)]
    use crate::v1::types::AddressFieldPathBuilder;
    #[allow(unused_imports)]
    use crate::v1::types::Digest;
    #[allow(unused_imports)]
    use crate::v1::types::DigestFieldPathBuilder;
    #[allow(unused_imports)]
    use crate::v1::types::ObjectId;
    #[allow(unused_imports)]
    use crate::v1::types::ObjectIdFieldPathBuilder;
    #[allow(unused_imports)]
    use crate::v1::types::Owner;
    #[allow(unused_imports)]
    use crate::v1::types::OwnerFieldPathBuilder;
    #[allow(unused_imports)]
    use crate::v1::types::TypeTag;
    #[allow(unused_imports)]
    use crate::v1::types::TypeTagFieldPathBuilder;
    impl Transaction {
        pub const DIGEST_FIELD: &'static MessageField = &MessageField {
            name: "digest",
            json_name: "digest",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Digest::FIELDS),
        };
        pub const BCS_FIELD: &'static MessageField = &MessageField {
            name: "bcs",
            json_name: "bcs",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(BcsData::FIELDS),
        };
    }
    impl MessageFields for Transaction {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::DIGEST_FIELD,
            Self::BCS_FIELD,
        ];
    }
    impl Transaction {
        pub fn path_builder() -> TransactionFieldPathBuilder {
            TransactionFieldPathBuilder::new()
        }
    }
    pub struct TransactionFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl TransactionFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn digest(mut self) -> DigestFieldPathBuilder {
            self.path.push(Transaction::DIGEST_FIELD.name);
            DigestFieldPathBuilder::new_with_base(self.path)
        }
        pub fn bcs(mut self) -> BcsDataFieldPathBuilder {
            self.path.push(Transaction::BCS_FIELD.name);
            BcsDataFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl TransactionEffects {
        pub const DIGEST_FIELD: &'static MessageField = &MessageField {
            name: "digest",
            json_name: "digest",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Digest::FIELDS),
        };
        pub const BCS_FIELD: &'static MessageField = &MessageField {
            name: "bcs",
            json_name: "bcs",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(BcsData::FIELDS),
        };
    }
    impl MessageFields for TransactionEffects {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::DIGEST_FIELD,
            Self::BCS_FIELD,
        ];
    }
    impl TransactionEffects {
        pub fn path_builder() -> TransactionEffectsFieldPathBuilder {
            TransactionEffectsFieldPathBuilder::new()
        }
    }
    pub struct TransactionEffectsFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl TransactionEffectsFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn digest(mut self) -> DigestFieldPathBuilder {
            self.path.push(TransactionEffects::DIGEST_FIELD.name);
            DigestFieldPathBuilder::new_with_base(self.path)
        }
        pub fn bcs(mut self) -> BcsDataFieldPathBuilder {
            self.path.push(TransactionEffects::BCS_FIELD.name);
            BcsDataFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl TransactionEvents {
        pub const DIGEST_FIELD: &'static MessageField = &MessageField {
            name: "digest",
            json_name: "digest",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Digest::FIELDS),
        };
        pub const EVENTS_FIELD: &'static MessageField = &MessageField {
            name: "events",
            json_name: "events",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Event::FIELDS),
        };
    }
    impl MessageFields for TransactionEvents {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::DIGEST_FIELD,
            Self::EVENTS_FIELD,
        ];
    }
    impl TransactionEvents {
        pub fn path_builder() -> TransactionEventsFieldPathBuilder {
            TransactionEventsFieldPathBuilder::new()
        }
    }
    pub struct TransactionEventsFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl TransactionEventsFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn digest(mut self) -> DigestFieldPathBuilder {
            self.path.push(TransactionEvents::DIGEST_FIELD.name);
            DigestFieldPathBuilder::new_with_base(self.path)
        }
        pub fn events(mut self) -> EventFieldPathBuilder {
            self.path.push(TransactionEvents::EVENTS_FIELD.name);
            EventFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ExecutedTransaction {
        pub const TRANSACTION_FIELD: &'static MessageField = &MessageField {
            name: "transaction",
            json_name: "transaction",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Transaction::FIELDS),
        };
        pub const SIGNATURES_FIELD: &'static MessageField = &MessageField {
            name: "signatures",
            json_name: "signatures",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(UserSignature::FIELDS),
        };
        pub const EFFECTS_FIELD: &'static MessageField = &MessageField {
            name: "effects",
            json_name: "effects",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(TransactionEffects::FIELDS),
        };
        pub const EVENTS_FIELD: &'static MessageField = &MessageField {
            name: "events",
            json_name: "events",
            number: 4i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(TransactionEvents::FIELDS),
        };
        pub const CHECKPOINT_FIELD: &'static MessageField = &MessageField {
            name: "checkpoint",
            json_name: "checkpoint",
            number: 5i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const TIMESTAMP_FIELD: &'static MessageField = &MessageField {
            name: "timestamp",
            json_name: "timestamp",
            number: 6i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const INPUT_OBJECTS_FIELD: &'static MessageField = &MessageField {
            name: "input_objects",
            json_name: "inputObjects",
            number: 7i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Object::FIELDS),
        };
        pub const OUTPUT_OBJECTS_FIELD: &'static MessageField = &MessageField {
            name: "output_objects",
            json_name: "outputObjects",
            number: 8i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Object::FIELDS),
        };
        pub const BALANCE_CHANGES_FIELD: &'static MessageField = &MessageField {
            name: "balance_changes",
            json_name: "balanceChanges",
            number: 9i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(BalanceChange::FIELDS),
        };
        pub const OBJECT_CHANGES_FIELD: &'static MessageField = &MessageField {
            name: "object_changes",
            json_name: "objectChanges",
            number: 10i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(ObjectChange::FIELDS),
        };
    }
    impl MessageFields for ExecutedTransaction {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::TRANSACTION_FIELD,
            Self::SIGNATURES_FIELD,
            Self::EFFECTS_FIELD,
            Self::EVENTS_FIELD,
            Self::CHECKPOINT_FIELD,
            Self::TIMESTAMP_FIELD,
            Self::INPUT_OBJECTS_FIELD,
            Self::OUTPUT_OBJECTS_FIELD,
            Self::BALANCE_CHANGES_FIELD,
            Self::OBJECT_CHANGES_FIELD,
        ];
    }
    impl ExecutedTransaction {
        pub fn path_builder() -> ExecutedTransactionFieldPathBuilder {
            ExecutedTransactionFieldPathBuilder::new()
        }
    }
    pub struct ExecutedTransactionFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ExecutedTransactionFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn transaction(mut self) -> TransactionFieldPathBuilder {
            self.path.push(ExecutedTransaction::TRANSACTION_FIELD.name);
            TransactionFieldPathBuilder::new_with_base(self.path)
        }
        pub fn signatures(mut self) -> UserSignatureFieldPathBuilder {
            self.path.push(ExecutedTransaction::SIGNATURES_FIELD.name);
            UserSignatureFieldPathBuilder::new_with_base(self.path)
        }
        pub fn effects(mut self) -> TransactionEffectsFieldPathBuilder {
            self.path.push(ExecutedTransaction::EFFECTS_FIELD.name);
            TransactionEffectsFieldPathBuilder::new_with_base(self.path)
        }
        pub fn events(mut self) -> TransactionEventsFieldPathBuilder {
            self.path.push(ExecutedTransaction::EVENTS_FIELD.name);
            TransactionEventsFieldPathBuilder::new_with_base(self.path)
        }
        pub fn checkpoint(mut self) -> String {
            self.path.push(ExecutedTransaction::CHECKPOINT_FIELD.name);
            self.finish()
        }
        pub fn timestamp(mut self) -> String {
            self.path.push(ExecutedTransaction::TIMESTAMP_FIELD.name);
            self.finish()
        }
        pub fn input_objects(mut self) -> ObjectFieldPathBuilder {
            self.path.push(ExecutedTransaction::INPUT_OBJECTS_FIELD.name);
            ObjectFieldPathBuilder::new_with_base(self.path)
        }
        pub fn output_objects(mut self) -> ObjectFieldPathBuilder {
            self.path.push(ExecutedTransaction::OUTPUT_OBJECTS_FIELD.name);
            ObjectFieldPathBuilder::new_with_base(self.path)
        }
        pub fn balance_changes(mut self) -> BalanceChangeFieldPathBuilder {
            self.path.push(ExecutedTransaction::BALANCE_CHANGES_FIELD.name);
            BalanceChangeFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_changes(mut self) -> ObjectChangeFieldPathBuilder {
            self.path.push(ExecutedTransaction::OBJECT_CHANGES_FIELD.name);
            ObjectChangeFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl BalanceChange {
        pub const OWNER_FIELD: &'static MessageField = &MessageField {
            name: "owner",
            json_name: "owner",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Owner::FIELDS),
        };
        pub const COIN_TYPE_FIELD: &'static MessageField = &MessageField {
            name: "coin_type",
            json_name: "coinType",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(TypeTag::FIELDS),
        };
        pub const AMOUNT_FIELD: &'static MessageField = &MessageField {
            name: "amount",
            json_name: "amount",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for BalanceChange {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::OWNER_FIELD,
            Self::COIN_TYPE_FIELD,
            Self::AMOUNT_FIELD,
        ];
    }
    impl BalanceChange {
        pub fn path_builder() -> BalanceChangeFieldPathBuilder {
            BalanceChangeFieldPathBuilder::new()
        }
    }
    pub struct BalanceChangeFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl BalanceChangeFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn owner(mut self) -> OwnerFieldPathBuilder {
            self.path.push(BalanceChange::OWNER_FIELD.name);
            OwnerFieldPathBuilder::new_with_base(self.path)
        }
        pub fn coin_type(mut self) -> TypeTagFieldPathBuilder {
            self.path.push(BalanceChange::COIN_TYPE_FIELD.name);
            TypeTagFieldPathBuilder::new_with_base(self.path)
        }
        pub fn amount(mut self) -> String {
            self.path.push(BalanceChange::AMOUNT_FIELD.name);
            self.finish()
        }
    }
    impl BalanceChanges {
        pub const BALANCE_CHANGES_FIELD: &'static MessageField = &MessageField {
            name: "balance_changes",
            json_name: "balanceChanges",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(BalanceChange::FIELDS),
        };
    }
    impl MessageFields for BalanceChanges {
        const FIELDS: &'static [&'static MessageField] = &[Self::BALANCE_CHANGES_FIELD];
    }
    impl BalanceChanges {
        pub fn path_builder() -> BalanceChangesFieldPathBuilder {
            BalanceChangesFieldPathBuilder::new()
        }
    }
    pub struct BalanceChangesFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl BalanceChangesFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn balance_changes(mut self) -> BalanceChangeFieldPathBuilder {
            self.path.push(BalanceChanges::BALANCE_CHANGES_FIELD.name);
            BalanceChangeFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ObjectChangePublished {
        pub const PACKAGE_ID_FIELD: &'static MessageField = &MessageField {
            name: "package_id",
            json_name: "packageId",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(ObjectId::FIELDS),
        };
        pub const VERSION_FIELD: &'static MessageField = &MessageField {
            name: "version",
            json_name: "version",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const DIGEST_FIELD: &'static MessageField = &MessageField {
            name: "digest",
            json_name: "digest",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Digest::FIELDS),
        };
        pub const MODULES_FIELD: &'static MessageField = &MessageField {
            name: "modules",
            json_name: "modules",
            number: 4i32,
            is_optional: false,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for ObjectChangePublished {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::PACKAGE_ID_FIELD,
            Self::VERSION_FIELD,
            Self::DIGEST_FIELD,
            Self::MODULES_FIELD,
        ];
    }
    impl ObjectChangePublished {
        pub fn path_builder() -> ObjectChangePublishedFieldPathBuilder {
            ObjectChangePublishedFieldPathBuilder::new()
        }
    }
    pub struct ObjectChangePublishedFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectChangePublishedFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn package_id(mut self) -> ObjectIdFieldPathBuilder {
            self.path.push(ObjectChangePublished::PACKAGE_ID_FIELD.name);
            ObjectIdFieldPathBuilder::new_with_base(self.path)
        }
        pub fn version(mut self) -> String {
            self.path.push(ObjectChangePublished::VERSION_FIELD.name);
            self.finish()
        }
        pub fn digest(mut self) -> DigestFieldPathBuilder {
            self.path.push(ObjectChangePublished::DIGEST_FIELD.name);
            DigestFieldPathBuilder::new_with_base(self.path)
        }
        pub fn modules(mut self) -> String {
            self.path.push(ObjectChangePublished::MODULES_FIELD.name);
            self.finish()
        }
    }
    impl ObjectChangeMutated {
        pub const SENDER_FIELD: &'static MessageField = &MessageField {
            name: "sender",
            json_name: "sender",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Address::FIELDS),
        };
        pub const OWNER_FIELD: &'static MessageField = &MessageField {
            name: "owner",
            json_name: "owner",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Owner::FIELDS),
        };
        pub const OBJECT_TYPE_FIELD: &'static MessageField = &MessageField {
            name: "object_type",
            json_name: "objectType",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(TypeTag::FIELDS),
        };
        pub const OBJECT_ID_FIELD: &'static MessageField = &MessageField {
            name: "object_id",
            json_name: "objectId",
            number: 4i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(ObjectId::FIELDS),
        };
        pub const VERSION_FIELD: &'static MessageField = &MessageField {
            name: "version",
            json_name: "version",
            number: 5i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const PREVIOUS_VERSION_FIELD: &'static MessageField = &MessageField {
            name: "previous_version",
            json_name: "previousVersion",
            number: 6i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const DIGEST_FIELD: &'static MessageField = &MessageField {
            name: "digest",
            json_name: "digest",
            number: 7i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Digest::FIELDS),
        };
    }
    impl MessageFields for ObjectChangeMutated {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::SENDER_FIELD,
            Self::OWNER_FIELD,
            Self::OBJECT_TYPE_FIELD,
            Self::OBJECT_ID_FIELD,
            Self::VERSION_FIELD,
            Self::PREVIOUS_VERSION_FIELD,
            Self::DIGEST_FIELD,
        ];
    }
    impl ObjectChangeMutated {
        pub fn path_builder() -> ObjectChangeMutatedFieldPathBuilder {
            ObjectChangeMutatedFieldPathBuilder::new()
        }
    }
    pub struct ObjectChangeMutatedFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectChangeMutatedFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn sender(mut self) -> AddressFieldPathBuilder {
            self.path.push(ObjectChangeMutated::SENDER_FIELD.name);
            AddressFieldPathBuilder::new_with_base(self.path)
        }
        pub fn owner(mut self) -> OwnerFieldPathBuilder {
            self.path.push(ObjectChangeMutated::OWNER_FIELD.name);
            OwnerFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_type(mut self) -> TypeTagFieldPathBuilder {
            self.path.push(ObjectChangeMutated::OBJECT_TYPE_FIELD.name);
            TypeTagFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_id(mut self) -> ObjectIdFieldPathBuilder {
            self.path.push(ObjectChangeMutated::OBJECT_ID_FIELD.name);
            ObjectIdFieldPathBuilder::new_with_base(self.path)
        }
        pub fn version(mut self) -> String {
            self.path.push(ObjectChangeMutated::VERSION_FIELD.name);
            self.finish()
        }
        pub fn previous_version(mut self) -> String {
            self.path.push(ObjectChangeMutated::PREVIOUS_VERSION_FIELD.name);
            self.finish()
        }
        pub fn digest(mut self) -> DigestFieldPathBuilder {
            self.path.push(ObjectChangeMutated::DIGEST_FIELD.name);
            DigestFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ObjectChangeDeleted {
        pub const SENDER_FIELD: &'static MessageField = &MessageField {
            name: "sender",
            json_name: "sender",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Address::FIELDS),
        };
        pub const OBJECT_TYPE_FIELD: &'static MessageField = &MessageField {
            name: "object_type",
            json_name: "objectType",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(TypeTag::FIELDS),
        };
        pub const OBJECT_ID_FIELD: &'static MessageField = &MessageField {
            name: "object_id",
            json_name: "objectId",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(ObjectId::FIELDS),
        };
        pub const VERSION_FIELD: &'static MessageField = &MessageField {
            name: "version",
            json_name: "version",
            number: 4i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for ObjectChangeDeleted {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::SENDER_FIELD,
            Self::OBJECT_TYPE_FIELD,
            Self::OBJECT_ID_FIELD,
            Self::VERSION_FIELD,
        ];
    }
    impl ObjectChangeDeleted {
        pub fn path_builder() -> ObjectChangeDeletedFieldPathBuilder {
            ObjectChangeDeletedFieldPathBuilder::new()
        }
    }
    pub struct ObjectChangeDeletedFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectChangeDeletedFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn sender(mut self) -> AddressFieldPathBuilder {
            self.path.push(ObjectChangeDeleted::SENDER_FIELD.name);
            AddressFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_type(mut self) -> TypeTagFieldPathBuilder {
            self.path.push(ObjectChangeDeleted::OBJECT_TYPE_FIELD.name);
            TypeTagFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_id(mut self) -> ObjectIdFieldPathBuilder {
            self.path.push(ObjectChangeDeleted::OBJECT_ID_FIELD.name);
            ObjectIdFieldPathBuilder::new_with_base(self.path)
        }
        pub fn version(mut self) -> String {
            self.path.push(ObjectChangeDeleted::VERSION_FIELD.name);
            self.finish()
        }
    }
    impl ObjectChangeWrapped {
        pub const SENDER_FIELD: &'static MessageField = &MessageField {
            name: "sender",
            json_name: "sender",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Address::FIELDS),
        };
        pub const OBJECT_TYPE_FIELD: &'static MessageField = &MessageField {
            name: "object_type",
            json_name: "objectType",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(TypeTag::FIELDS),
        };
        pub const OBJECT_ID_FIELD: &'static MessageField = &MessageField {
            name: "object_id",
            json_name: "objectId",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(ObjectId::FIELDS),
        };
        pub const VERSION_FIELD: &'static MessageField = &MessageField {
            name: "version",
            json_name: "version",
            number: 4i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for ObjectChangeWrapped {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::SENDER_FIELD,
            Self::OBJECT_TYPE_FIELD,
            Self::OBJECT_ID_FIELD,
            Self::VERSION_FIELD,
        ];
    }
    impl ObjectChangeWrapped {
        pub fn path_builder() -> ObjectChangeWrappedFieldPathBuilder {
            ObjectChangeWrappedFieldPathBuilder::new()
        }
    }
    pub struct ObjectChangeWrappedFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectChangeWrappedFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn sender(mut self) -> AddressFieldPathBuilder {
            self.path.push(ObjectChangeWrapped::SENDER_FIELD.name);
            AddressFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_type(mut self) -> TypeTagFieldPathBuilder {
            self.path.push(ObjectChangeWrapped::OBJECT_TYPE_FIELD.name);
            TypeTagFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_id(mut self) -> ObjectIdFieldPathBuilder {
            self.path.push(ObjectChangeWrapped::OBJECT_ID_FIELD.name);
            ObjectIdFieldPathBuilder::new_with_base(self.path)
        }
        pub fn version(mut self) -> String {
            self.path.push(ObjectChangeWrapped::VERSION_FIELD.name);
            self.finish()
        }
    }
    impl ObjectChangeUnwrapped {
        pub const SENDER_FIELD: &'static MessageField = &MessageField {
            name: "sender",
            json_name: "sender",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Address::FIELDS),
        };
        pub const OWNER_FIELD: &'static MessageField = &MessageField {
            name: "owner",
            json_name: "owner",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Owner::FIELDS),
        };
        pub const OBJECT_TYPE_FIELD: &'static MessageField = &MessageField {
            name: "object_type",
            json_name: "objectType",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(TypeTag::FIELDS),
        };
        pub const OBJECT_ID_FIELD: &'static MessageField = &MessageField {
            name: "object_id",
            json_name: "objectId",
            number: 4i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(ObjectId::FIELDS),
        };
        pub const VERSION_FIELD: &'static MessageField = &MessageField {
            name: "version",
            json_name: "version",
            number: 5i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const DIGEST_FIELD: &'static MessageField = &MessageField {
            name: "digest",
            json_name: "digest",
            number: 6i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Digest::FIELDS),
        };
    }
    impl MessageFields for ObjectChangeUnwrapped {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::SENDER_FIELD,
            Self::OWNER_FIELD,
            Self::OBJECT_TYPE_FIELD,
            Self::OBJECT_ID_FIELD,
            Self::VERSION_FIELD,
            Self::DIGEST_FIELD,
        ];
    }
    impl ObjectChangeUnwrapped {
        pub fn path_builder() -> ObjectChangeUnwrappedFieldPathBuilder {
            ObjectChangeUnwrappedFieldPathBuilder::new()
        }
    }
    pub struct ObjectChangeUnwrappedFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectChangeUnwrappedFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn sender(mut self) -> AddressFieldPathBuilder {
            self.path.push(ObjectChangeUnwrapped::SENDER_FIELD.name);
            AddressFieldPathBuilder::new_with_base(self.path)
        }
        pub fn owner(mut self) -> OwnerFieldPathBuilder {
            self.path.push(ObjectChangeUnwrapped::OWNER_FIELD.name);
            OwnerFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_type(mut self) -> TypeTagFieldPathBuilder {
            self.path.push(ObjectChangeUnwrapped::OBJECT_TYPE_FIELD.name);
            TypeTagFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_id(mut self) -> ObjectIdFieldPathBuilder {
            self.path.push(ObjectChangeUnwrapped::OBJECT_ID_FIELD.name);
            ObjectIdFieldPathBuilder::new_with_base(self.path)
        }
        pub fn version(mut self) -> String {
            self.path.push(ObjectChangeUnwrapped::VERSION_FIELD.name);
            self.finish()
        }
        pub fn digest(mut self) -> DigestFieldPathBuilder {
            self.path.push(ObjectChangeUnwrapped::DIGEST_FIELD.name);
            DigestFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ObjectChangeCreated {
        pub const SENDER_FIELD: &'static MessageField = &MessageField {
            name: "sender",
            json_name: "sender",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Address::FIELDS),
        };
        pub const OWNER_FIELD: &'static MessageField = &MessageField {
            name: "owner",
            json_name: "owner",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Owner::FIELDS),
        };
        pub const OBJECT_TYPE_FIELD: &'static MessageField = &MessageField {
            name: "object_type",
            json_name: "objectType",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(TypeTag::FIELDS),
        };
        pub const OBJECT_ID_FIELD: &'static MessageField = &MessageField {
            name: "object_id",
            json_name: "objectId",
            number: 4i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(ObjectId::FIELDS),
        };
        pub const VERSION_FIELD: &'static MessageField = &MessageField {
            name: "version",
            json_name: "version",
            number: 5i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const DIGEST_FIELD: &'static MessageField = &MessageField {
            name: "digest",
            json_name: "digest",
            number: 6i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Digest::FIELDS),
        };
    }
    impl MessageFields for ObjectChangeCreated {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::SENDER_FIELD,
            Self::OWNER_FIELD,
            Self::OBJECT_TYPE_FIELD,
            Self::OBJECT_ID_FIELD,
            Self::VERSION_FIELD,
            Self::DIGEST_FIELD,
        ];
    }
    impl ObjectChangeCreated {
        pub fn path_builder() -> ObjectChangeCreatedFieldPathBuilder {
            ObjectChangeCreatedFieldPathBuilder::new()
        }
    }
    pub struct ObjectChangeCreatedFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectChangeCreatedFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn sender(mut self) -> AddressFieldPathBuilder {
            self.path.push(ObjectChangeCreated::SENDER_FIELD.name);
            AddressFieldPathBuilder::new_with_base(self.path)
        }
        pub fn owner(mut self) -> OwnerFieldPathBuilder {
            self.path.push(ObjectChangeCreated::OWNER_FIELD.name);
            OwnerFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_type(mut self) -> TypeTagFieldPathBuilder {
            self.path.push(ObjectChangeCreated::OBJECT_TYPE_FIELD.name);
            TypeTagFieldPathBuilder::new_with_base(self.path)
        }
        pub fn object_id(mut self) -> ObjectIdFieldPathBuilder {
            self.path.push(ObjectChangeCreated::OBJECT_ID_FIELD.name);
            ObjectIdFieldPathBuilder::new_with_base(self.path)
        }
        pub fn version(mut self) -> String {
            self.path.push(ObjectChangeCreated::VERSION_FIELD.name);
            self.finish()
        }
        pub fn digest(mut self) -> DigestFieldPathBuilder {
            self.path.push(ObjectChangeCreated::DIGEST_FIELD.name);
            DigestFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ObjectChange {
        pub const PUBLISHED_FIELD: &'static MessageField = &MessageField {
            name: "published",
            json_name: "published",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ObjectChangePublished::FIELDS),
        };
        pub const MUTATED_FIELD: &'static MessageField = &MessageField {
            name: "mutated",
            json_name: "mutated",
            number: 2i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ObjectChangeMutated::FIELDS),
        };
        pub const DELETED_FIELD: &'static MessageField = &MessageField {
            name: "deleted",
            json_name: "deleted",
            number: 3i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ObjectChangeDeleted::FIELDS),
        };
        pub const WRAPPED_FIELD: &'static MessageField = &MessageField {
            name: "wrapped",
            json_name: "wrapped",
            number: 4i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ObjectChangeWrapped::FIELDS),
        };
        pub const UNWRAPPED_FIELD: &'static MessageField = &MessageField {
            name: "unwrapped",
            json_name: "unwrapped",
            number: 5i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ObjectChangeUnwrapped::FIELDS),
        };
        pub const CREATED_FIELD: &'static MessageField = &MessageField {
            name: "created",
            json_name: "created",
            number: 6i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ObjectChangeCreated::FIELDS),
        };
    }
    impl ObjectChange {
        pub const KIND_ONEOF: &'static str = "kind";
    }
    impl MessageFields for ObjectChange {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::PUBLISHED_FIELD,
            Self::MUTATED_FIELD,
            Self::DELETED_FIELD,
            Self::WRAPPED_FIELD,
            Self::UNWRAPPED_FIELD,
            Self::CREATED_FIELD,
        ];
        const ONEOFS: &'static [&'static str] = &["kind"];
    }
    impl ObjectChange {
        pub fn path_builder() -> ObjectChangeFieldPathBuilder {
            ObjectChangeFieldPathBuilder::new()
        }
    }
    pub struct ObjectChangeFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectChangeFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn published(mut self) -> ObjectChangePublishedFieldPathBuilder {
            self.path.push(ObjectChange::PUBLISHED_FIELD.name);
            ObjectChangePublishedFieldPathBuilder::new_with_base(self.path)
        }
        pub fn mutated(mut self) -> ObjectChangeMutatedFieldPathBuilder {
            self.path.push(ObjectChange::MUTATED_FIELD.name);
            ObjectChangeMutatedFieldPathBuilder::new_with_base(self.path)
        }
        pub fn deleted(mut self) -> ObjectChangeDeletedFieldPathBuilder {
            self.path.push(ObjectChange::DELETED_FIELD.name);
            ObjectChangeDeletedFieldPathBuilder::new_with_base(self.path)
        }
        pub fn wrapped(mut self) -> ObjectChangeWrappedFieldPathBuilder {
            self.path.push(ObjectChange::WRAPPED_FIELD.name);
            ObjectChangeWrappedFieldPathBuilder::new_with_base(self.path)
        }
        pub fn unwrapped(mut self) -> ObjectChangeUnwrappedFieldPathBuilder {
            self.path.push(ObjectChange::UNWRAPPED_FIELD.name);
            ObjectChangeUnwrappedFieldPathBuilder::new_with_base(self.path)
        }
        pub fn created(mut self) -> ObjectChangeCreatedFieldPathBuilder {
            self.path.push(ObjectChange::CREATED_FIELD.name);
            ObjectChangeCreatedFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ObjectChanges {
        pub const OBJECT_CHANGES_FIELD: &'static MessageField = &MessageField {
            name: "object_changes",
            json_name: "objectChanges",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ObjectChange::FIELDS),
        };
    }
    impl MessageFields for ObjectChanges {
        const FIELDS: &'static [&'static MessageField] = &[Self::OBJECT_CHANGES_FIELD];
    }
    impl ObjectChanges {
        pub fn path_builder() -> ObjectChangesFieldPathBuilder {
            ObjectChangesFieldPathBuilder::new()
        }
    }
    pub struct ObjectChangesFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectChangesFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn object_changes(mut self) -> ObjectChangeFieldPathBuilder {
            self.path.push(ObjectChanges::OBJECT_CHANGES_FIELD.name);
            ObjectChangeFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ExecutedTransactions {
        pub const EXECUTED_TRANSACTIONS_FIELD: &'static MessageField = &MessageField {
            name: "executed_transactions",
            json_name: "executedTransactions",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ExecutedTransaction::FIELDS),
        };
    }
    impl MessageFields for ExecutedTransactions {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::EXECUTED_TRANSACTIONS_FIELD,
        ];
    }
    impl ExecutedTransactions {
        pub fn path_builder() -> ExecutedTransactionsFieldPathBuilder {
            ExecutedTransactionsFieldPathBuilder::new()
        }
    }
    pub struct ExecutedTransactionsFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ExecutedTransactionsFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn executed_transactions(mut self) -> ExecutedTransactionFieldPathBuilder {
            self.path.push(ExecutedTransactions::EXECUTED_TRANSACTIONS_FIELD.name);
            ExecutedTransactionFieldPathBuilder::new_with_base(self.path)
        }
    }
}
pub use _field_impls::*;
