// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Core type definitions for the IOTA blockchain.
//!
//! [IOTA] is a next-generation smart contract platform with high throughput,
//! low latency, and an asset-oriented programming model powered by the Move
//! programming language. This crate provides type definitions for working with
//! the data that makes up the IOTA blockchain.
//!
//! [IOTA]: https://iota.org
//!
//! # Feature flags
//!
//! This library uses a set of [feature flags] to reduce the number of
//! dependencies and amount of compiled code. By default, no features are
//! enabled which allows one to enable a subset specifically for their use case.
//! Below is a list of the available feature flags.
//!
//! - `schemars`: Enables JSON schema generation using the [schemars] library.
//! - `serde`: Enables support for serializing and deserializing types to/from
//!   BCS utilizing [serde] library.
//! - `rand`: Enables support for generating random instances of a number of
//!   types via the [rand] library.
//! - `hash`: Enables support for hashing, which is required for deriving
//!   addresses and calculating digests for various types.
//! - `proptest`: Enables support for the [proptest] library by providing
//!   implementations of [proptest::arbitrary::Arbitrary] for many types.
//!
//! [feature flags]: https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section
//! [serde]: https://docs.rs/serde
//! [rand]: https://docs.rs/rand
//! [proptest]: https://docs.rs/proptest
//! [schemars]: https://docs.rs/schemars
//! [proptest::arbitrary::Arbitrary]: https://docs.rs/proptest/latest/proptest/arbitrary/trait.Arbitrary.html
//!
//! # BCS
//!
//! [BCS] is the serialization format used to represent the state of the
//! blockchain and is used extensively throughout the IOTA ecosystem. In
//! particular the BCS format is leveraged because it _"guarantees canonical
//! serialization, meaning that for any given data type, there is a one-to-one
//! correspondence between in-memory values and valid byte representations."_
//! One benefit of this property of having a canonical serialized representation
//! is to allow different entities in the ecosystem to all agree on how a
//! particular type should be interpreted and more importantly define a
//! deterministic representation for hashing and signing.
//!
//! This library strives to guarantee that the types defined are fully
//! BCS-compatible with the data that the network produces. The one caveat to
//! this would be that as the IOTA protocol evolves, new type variants are added
//! and older versions of this library may not support those newly
//! added variants. The expectation is that the most recent release of this
//! library will support new variants and types as they are released to IOTA's
//! `testnet` network.
//!
//! See the documentation for the various types defined by this crate for a
//! specification of their BCS serialized representation which will be defined
//! using ABNF notation as described by [RFC-5234]. In addition to the format
//! itself, some types have an extra layer of verification and may impose
//! additional restrictions on valid byte representations above and beyond those
//! already provided by BCS. In these instances the documentation for those
//! types will clearly specify these additional restrictions.
//!
//! Here are some common rules:
//!
//! ```text
//! ; --- BCS Value ---
//! bcs-value           = bcs-struct / bcs-enum / bcs-length-prefixed / bcs-fixed-length
//! bcs-length-prefixed = bytes / string / vector / option
//! bcs-fixed-length    = u8 / u16 / u32 / u64 / u128 /
//!                       i8 / i16 / i32 / i64 / i128 /
//!                       boolean
//! bcs-struct          = *bcs-value                ; Sequence of serialized fields
//! bcs-enum            = uleb128-index bcs-value   ; Enum index and associated value
//!
//! ; --- Length-prefixed types ---
//! bytes           = uleb128 *OCTET          ; Raw bytes of the specified length
//! string          = uleb128 *OCTET          ; valid utf8 string of the specified length
//! vector          = uleb128 *bcs-value      ; Length-prefixed list of values
//! option          = %x00 / (%x01 bcs-value) ; optional value
//!
//! ; --- Fixed-length types ---
//! u8          = OCTET                     ; 1-byte unsigned integer
//! u16         = 2OCTET                    ; 2-byte unsigned integer, little-endian
//! u32         = 4OCTET                    ; 4-byte unsigned integer, little-endian
//! u64         = 8OCTET                    ; 8-byte unsigned integer, little-endian
//! u128        = 16OCTET                   ; 16-byte unsigned integer, little-endian
//! i8          = OCTET                     ; 1-byte signed integer
//! i16         = 2OCTET                    ; 2-byte signed integer, little-endian
//! i32         = 4OCTET                    ; 4-byte signed integer, little-endian
//! i64         = 8OCTET                    ; 8-byte signed integer, little-endian
//! i128        = 16OCTET                   ; 16-byte signed integer, little-endian
//! boolean     = %x00 / %x01               ; Boolean: 0 = false, 1 = true
//! array       = *(bcs-value)              ; Fixed-length array
//!
//! ; --- ULEB128 definition ---
//! uleb128         = 1*5uleb128-byte       ; Variable-length ULEB128 encoding
//! uleb128-byte    = %x00-7F / %x80-FF     ; ULEB128 continuation rules
//! uleb128-index   = uleb128               ; ULEB128-encoded variant index
//! ```
//!
//! [BCS]: https://docs.rs/bcs
//! [RFC-5234]: https://datatracker.ietf.org/doc/html/rfc5234

#![expect(unused)]
#![allow(clippy::wrong_self_convention)]

mod crypto;
mod error;
mod faucet;
mod graphql;
mod transaction_builder;
mod types;
mod uniffi_helpers;

uniffi::setup_scaffolding!();
