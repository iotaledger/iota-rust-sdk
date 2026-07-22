// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod _accessor_impls {
    #![allow(clippy::useless_conversion)]
    impl super::Address {
        /// Sets `address` with the provided value.
        pub fn with_address<T: Into<::prost::bytes::Bytes>>(mut self, field: T) -> Self {
            self.address = field.into();
            self
        }
    }
    impl super::Digest {
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<::prost::bytes::Bytes>>(mut self, field: T) -> Self {
            self.digest = field.into();
            self
        }
    }
    impl super::ObjectId {
        /// Sets `object_id` with the provided value.
        pub fn with_object_id<T: Into<::prost::bytes::Bytes>>(
            mut self,
            field: T,
        ) -> Self {
            self.object_id = field.into();
            self
        }
    }
    impl super::ObjectReference {
        /// Sets `object_id` with the provided value.
        pub fn with_object_id<T: Into<super::ObjectId>>(mut self, field: T) -> Self {
            self.object_id = Some(field.into());
            self
        }
        /// Sets `version` with the provided value.
        pub fn with_version(mut self, field: u64) -> Self {
            self.version = Some(field);
            self
        }
        /// Sets `digest` with the provided value.
        pub fn with_digest<T: Into<super::Digest>>(mut self, field: T) -> Self {
            self.digest = Some(field.into());
            self
        }
    }
    impl super::Owner {
        /// Sets `address_owner` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_address_owner<T: Into<super::Address>>(mut self, field: T) -> Self {
            self.kind = Some(super::owner::Kind::AddressOwner(field.into()));
            self
        }
        /// Sets `object_owner` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_object_owner<T: Into<super::ObjectId>>(mut self, field: T) -> Self {
            self.kind = Some(super::owner::Kind::ObjectOwner(field.into()));
            self
        }
        /// Sets `shared` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_shared(mut self, field: u64) -> Self {
            self.kind = Some(super::owner::Kind::Shared(field));
            self
        }
        /// Sets `immutable` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_immutable(mut self, field: bool) -> Self {
            self.kind = Some(super::owner::Kind::Immutable(field));
            self
        }
    }
}
