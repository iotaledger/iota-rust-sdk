// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod _accessor_impls {
    #![allow(clippy::useless_conversion)]
    impl super::BalanceChange {
        /// Sets `owner` with the provided value.
        pub fn with_owner<T: Into<super::super::types::Owner>>(
            mut self,
            field: T,
        ) -> Self {
            self.owner = Some(field.into());
            self
        }
        /// Sets `coin_type` with the provided value.
        pub fn with_coin_type<T: Into<super::super::types::TypeTag>>(
            mut self,
            field: T,
        ) -> Self {
            self.coin_type = Some(field.into());
            self
        }
        /// Sets `amount` with the provided value.
        pub fn with_amount<T: Into<String>>(mut self, field: T) -> Self {
            self.amount = Some(field.into());
            self
        }
    }
    impl super::BalanceChanges {
        /// Sets `balance_changes` with the provided value.
        pub fn with_balance_changes(mut self, field: Vec<super::BalanceChange>) -> Self {
            self.balance_changes = field;
            self
        }
    }
    impl super::ExecutedTransaction {
        /// Sets `transaction` with the provided value.
        pub fn with_transaction<T: Into<super::Transaction>>(
            mut self,
            field: T,
        ) -> Self {
            self.transaction = Some(field.into());
            self
        }
        /// Sets `signatures` with the provided value.
        pub fn with_signatures<T: Into<super::super::signatures::UserSignatures>>(
            mut self,
            field: T,
        ) -> Self {
            self.signatures = Some(field.into());
            self
        }
        /// Sets `effects` with the provided value.
        pub fn with_effects<T: Into<super::TransactionEffects>>(
            mut self,
            field: T,
        ) -> Self {
            self.effects = Some(field.into());
            self
        }
        /// Sets `events` with the provided value.
        pub fn with_events<T: Into<super::TransactionEvents>>(
            mut self,
            field: T,
        ) -> Self {
            self.events = Some(field.into());
            self
        }
        /// Sets `checkpoint` with the provided value.
        pub fn with_checkpoint(mut self, field: u64) -> Self {
            self.checkpoint = Some(field);
            self
        }
        /// Sets `timestamp` with the provided value.
        pub fn with_timestamp<T: Into<::prost_types::Timestamp>>(
            mut self,
            field: T,
        ) -> Self {
            self.timestamp = Some(field.into());
            self
        }
        /// Sets `input_objects` with the provided value.
        pub fn with_input_objects<T: Into<super::super::object::Objects>>(
            mut self,
            field: T,
        ) -> Self {
            self.input_objects = Some(field.into());
            self
        }
        /// Sets `output_objects` with the provided value.
        pub fn with_output_objects<T: Into<super::super::object::Objects>>(
            mut self,
            field: T,
        ) -> Self {
            self.output_objects = Some(field.into());
            self
        }
        /// Sets `balance_changes` with the provided value.
        pub fn with_balance_changes<T: Into<super::BalanceChanges>>(
            mut self,
            field: T,
        ) -> Self {
            self.balance_changes = Some(field.into());
            self
        }
        /// Sets `object_changes` with the provided value.
        pub fn with_object_changes<T: Into<super::ObjectChanges>>(
            mut self,
            field: T,
        ) -> Self {
            self.object_changes = Some(field.into());
            self
        }
    }
    impl super::ExecutedTransactions {
        /// Sets `executed_transactions` with the provided value.
        pub fn with_executed_transactions(
            mut self,
            field: Vec<super::ExecutedTransaction>,
        ) -> Self {
            self.executed_transactions = field;
            self
        }
    }
    impl super::ObjectChange {
        /// Sets `published` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_published<T: Into<super::ObjectChangePublished>>(
            mut self,
            field: T,
        ) -> Self {
            self.kind = Some(super::object_change::Kind::Published(field.into()));
            self
        }
        /// Sets `mutated` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_mutated<T: Into<super::ObjectChangeMutated>>(
            mut self,
            field: T,
        ) -> Self {
            self.kind = Some(super::object_change::Kind::Mutated(field.into()));
            self
        }
        /// Sets `deleted` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_deleted<T: Into<super::ObjectChangeDeleted>>(
            mut self,
            field: T,
        ) -> Self {
            self.kind = Some(super::object_change::Kind::Deleted(field.into()));
            self
        }
        /// Sets `wrapped` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_wrapped<T: Into<super::ObjectChangeWrapped>>(
            mut self,
            field: T,
        ) -> Self {
            self.kind = Some(super::object_change::Kind::Wrapped(field.into()));
            self
        }
        /// Sets `unwrapped` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_unwrapped<T: Into<super::ObjectChangeUnwrapped>>(
            mut self,
            field: T,
        ) -> Self {
            self.kind = Some(super::object_change::Kind::Unwrapped(field.into()));
            self
        }
        /// Sets `created` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_created<T: Into<super::ObjectChangeCreated>>(
            mut self,
            field: T,
        ) -> Self {
            self.kind = Some(super::object_change::Kind::Created(field.into()));
            self
        }
    }
    impl super::ObjectChangeCreated {
        /// Sets `sender` with the provided value.
        pub fn with_sender<T: Into<super::super::types::Address>>(
            mut self,
            field: T,
        ) -> Self {
            self.sender = Some(field.into());
            self
        }
        /// Sets `owner` with the provided value.
        pub fn with_owner<T: Into<super::super::types::Owner>>(
            mut self,
            field: T,
        ) -> Self {
            self.owner = Some(field.into());
            self
        }
        /// Sets `object_type` with the provided value.
        pub fn with_object_type<T: Into<String>>(mut self, field: T) -> Self {
            self.object_type = Some(field.into());
            self
        }
        /// Sets `object_id` with the provided value.
        pub fn with_object_id<T: Into<super::super::types::ObjectId>>(
            mut self,
            field: T,
        ) -> Self {
            self.object_id = Some(field.into());
            self
        }
        /// Sets `version` with the provided value.
        pub fn with_version(mut self, field: u64) -> Self {
            self.version = Some(field);
            self
        }
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<super::super::types::Digest>>(
            mut self,
            field: T,
        ) -> Self {
            self.digest = Some(field.into());
            self
        }
    }
    impl super::ObjectChangeDeleted {
        /// Sets `sender` with the provided value.
        pub fn with_sender<T: Into<super::super::types::Address>>(
            mut self,
            field: T,
        ) -> Self {
            self.sender = Some(field.into());
            self
        }
        /// Sets `object_type` with the provided value.
        pub fn with_object_type<T: Into<String>>(mut self, field: T) -> Self {
            self.object_type = Some(field.into());
            self
        }
        /// Sets `object_id` with the provided value.
        pub fn with_object_id<T: Into<super::super::types::ObjectId>>(
            mut self,
            field: T,
        ) -> Self {
            self.object_id = Some(field.into());
            self
        }
        /// Sets `version` with the provided value.
        pub fn with_version(mut self, field: u64) -> Self {
            self.version = Some(field);
            self
        }
    }
    impl super::ObjectChangeMutated {
        /// Sets `sender` with the provided value.
        pub fn with_sender<T: Into<super::super::types::Address>>(
            mut self,
            field: T,
        ) -> Self {
            self.sender = Some(field.into());
            self
        }
        /// Sets `owner` with the provided value.
        pub fn with_owner<T: Into<super::super::types::Owner>>(
            mut self,
            field: T,
        ) -> Self {
            self.owner = Some(field.into());
            self
        }
        /// Sets `object_type` with the provided value.
        pub fn with_object_type<T: Into<String>>(mut self, field: T) -> Self {
            self.object_type = Some(field.into());
            self
        }
        /// Sets `object_id` with the provided value.
        pub fn with_object_id<T: Into<super::super::types::ObjectId>>(
            mut self,
            field: T,
        ) -> Self {
            self.object_id = Some(field.into());
            self
        }
        /// Sets `version` with the provided value.
        pub fn with_version(mut self, field: u64) -> Self {
            self.version = Some(field);
            self
        }
        /// Sets `previous_version` with the provided value.
        pub fn with_previous_version(mut self, field: u64) -> Self {
            self.previous_version = Some(field);
            self
        }
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<super::super::types::Digest>>(
            mut self,
            field: T,
        ) -> Self {
            self.digest = Some(field.into());
            self
        }
    }
    impl super::ObjectChangePublished {
        /// Sets `package_id` with the provided value.
        pub fn with_package_id<T: Into<super::super::types::ObjectId>>(
            mut self,
            field: T,
        ) -> Self {
            self.package_id = Some(field.into());
            self
        }
        /// Sets `version` with the provided value.
        pub fn with_version(mut self, field: u64) -> Self {
            self.version = Some(field);
            self
        }
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<super::super::types::Digest>>(
            mut self,
            field: T,
        ) -> Self {
            self.digest = Some(field.into());
            self
        }
        /// Sets `modules` with the provided value.
        pub fn with_modules(mut self, field: Vec<String>) -> Self {
            self.modules = field;
            self
        }
    }
    impl super::ObjectChangeUnwrapped {
        /// Sets `sender` with the provided value.
        pub fn with_sender<T: Into<super::super::types::Address>>(
            mut self,
            field: T,
        ) -> Self {
            self.sender = Some(field.into());
            self
        }
        /// Sets `owner` with the provided value.
        pub fn with_owner<T: Into<super::super::types::Owner>>(
            mut self,
            field: T,
        ) -> Self {
            self.owner = Some(field.into());
            self
        }
        /// Sets `object_type` with the provided value.
        pub fn with_object_type<T: Into<String>>(mut self, field: T) -> Self {
            self.object_type = Some(field.into());
            self
        }
        /// Sets `object_id` with the provided value.
        pub fn with_object_id<T: Into<super::super::types::ObjectId>>(
            mut self,
            field: T,
        ) -> Self {
            self.object_id = Some(field.into());
            self
        }
        /// Sets `version` with the provided value.
        pub fn with_version(mut self, field: u64) -> Self {
            self.version = Some(field);
            self
        }
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<super::super::types::Digest>>(
            mut self,
            field: T,
        ) -> Self {
            self.digest = Some(field.into());
            self
        }
    }
    impl super::ObjectChangeWrapped {
        /// Sets `sender` with the provided value.
        pub fn with_sender<T: Into<super::super::types::Address>>(
            mut self,
            field: T,
        ) -> Self {
            self.sender = Some(field.into());
            self
        }
        /// Sets `object_type` with the provided value.
        pub fn with_object_type<T: Into<String>>(mut self, field: T) -> Self {
            self.object_type = Some(field.into());
            self
        }
        /// Sets `object_id` with the provided value.
        pub fn with_object_id<T: Into<super::super::types::ObjectId>>(
            mut self,
            field: T,
        ) -> Self {
            self.object_id = Some(field.into());
            self
        }
        /// Sets `version` with the provided value.
        pub fn with_version(mut self, field: u64) -> Self {
            self.version = Some(field);
            self
        }
    }
    impl super::ObjectChanges {
        /// Sets `object_changes` with the provided value.
        pub fn with_object_changes(mut self, field: Vec<super::ObjectChange>) -> Self {
            self.object_changes = field;
            self
        }
    }
    impl super::Transaction {
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<super::super::types::Digest>>(
            mut self,
            field: T,
        ) -> Self {
            self.digest = Some(field.into());
            self
        }
        /// Sets `bcs` with the provided value.
        pub fn with_bcs<T: Into<super::super::bcs::BcsData>>(
            mut self,
            field: T,
        ) -> Self {
            self.bcs = Some(field.into());
            self
        }
    }
    impl super::TransactionEffects {
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<super::super::types::Digest>>(
            mut self,
            field: T,
        ) -> Self {
            self.digest = Some(field.into());
            self
        }
        /// Sets `bcs` with the provided value.
        pub fn with_bcs<T: Into<super::super::bcs::BcsData>>(
            mut self,
            field: T,
        ) -> Self {
            self.bcs = Some(field.into());
            self
        }
    }
    impl super::TransactionEvents {
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<super::super::types::Digest>>(
            mut self,
            field: T,
        ) -> Self {
            self.digest = Some(field.into());
            self
        }
        /// Sets `events` with the provided value.
        pub fn with_events<T: Into<super::super::event::Events>>(
            mut self,
            field: T,
        ) -> Self {
            self.events = Some(field.into());
            self
        }
    }
}
