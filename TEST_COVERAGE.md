# Test Coverage Improvements

This document summarizes the unit tests added to increase test coverage across three crates in the IOTA Rust SDK.

## Overview

| Crate | Files Modified | Tests Added |
|-------|---------------|-------------|
| `iota-sdk-types` | 6 | 178 |
| `iota-sdk-transaction-builder` | 5 | 138 |
| `iota-sdk-graphql-client` | 5 | 71 |
| **Total** | **16** | **387** |

**Coverage improvement: 47.84% → 64.08% = +16.24% line coverage increase**

## Running the Tests

```bash
# iota-sdk-types (requires --all-features for proptest support)
cargo +nightly test -p iota-sdk-types --lib --all-features

# iota-sdk-transaction-builder
cargo +nightly test -p iota-sdk-transaction-builder --lib

# iota-sdk-graphql-client
cargo +nightly test -p iota-sdk-graphql-client --lib
```

> **Note:** Some pre-existing tests in `iota-sdk-transaction-builder` and `iota-sdk-graphql-client` require a running localnet and will fail without one. All newly added tests are fully offline and self-contained.

---

## iota-sdk-types

### `src/crypto/zklogin.rs` — Meaningful Logic Tests

Tests for ZkLogin authentication logic including claim verification, JWT parsing, and field element encoding.

- **`ZkLoginClaim::verify_extended_claim()`**: valid ISS claim extraction, invalid base64 input, too-short claims, invalid `index_mod_4`, missing JSON key, error display formatting
- **`JwtHeader::from_base64()`**: valid RS256 header parsing, wrong algorithm rejection (HS256), invalid base64 input, missing `kid` field
- **`ZkLoginInputs::new()`**: full construction with claim verification, ISS extraction, JWT header validation
- **`Bn254FieldElement`**: `unpadded()` zero-stripping logic, `from_str_radix_10()` parsing, edge cases for all-zeros and leading-zero bytes

### `src/crypto/passkey.rs` — Validation & Serialization Tests

Tests for passkey authenticator validation logic and serialization roundtrips.

- **`PasskeyAuthenticator::new()`**: rejects Ed25519 signatures (requires Secp256r1), rejects invalid JSON in client_data_json, rejects invalid base64url challenge, accepts valid construction
- **`PasskeyAuthenticator::from_serialized_bytes()`**: empty bytes, wrong signature scheme flag, invalid BCS data
- **Roundtrip serialization**: `to_bytes()` → `from_serialized_bytes()` produces identical authenticator
- **Challenge parsing**: verifies challenge is correctly decoded from client_data_json

### `src/crypto/move_authenticator.rs` — Construction & Serialization Tests

Tests for MoveAuthenticator construction, address extraction, and serialization.

- **`new_immutable()`**: creates correct `ImmutableOrOwned` input variant
- **`new_shared()`**: creates `Shared` input with `mutable=false`, correct object_id and initial_shared_version
- **`address()`**: extracts correct address from both immutable and shared variants via pattern matching
- **Roundtrip serialization**: `to_bytes()` → `from_serialized_bytes()` for immutable, shared, and with call_args/type_args
- **Error paths**: empty bytes, wrong flag, invalid BCS, unknown signature scheme flag

### `src/crypto/multisig.rs` — Committee Validation Tests

Tests for multisig committee `is_valid()` validation logic.

- **Valid committees**: single member, multiple members, max 10 members, mixed key types, threshold less than total weight
- **Invalid committees**: zero threshold, empty members, >10 members, zero-weight member, weight sum < threshold, duplicate members
- **Aggregated signatures**: construction, bitmap access, signature collection

### `src/object.rs` — Core Object Type Tests

Tests for object reference types, owner variants, and object data.

- **ObjectReference**: construction, `Hash`/`Eq` consistency, `Ord` ordering
- **Owner**: all four variants, variant checks, `Ord` implementation
- **ObjectData/ObjectType**: `Struct` and `Package` variants
- **Object**: construction, field accessors
- **GenesisObject/BalanceChange**: construction and field access

### `src/events.rs` — Event Type Tests

- **Event**: construction, field access, `Clone`/`Eq`
- **TransactionEvents**: construction, data access
- **BalanceChange**: positive/negative amounts, `Ord` ordering

---

## iota-sdk-transaction-builder

### `src/builder/mod.rs` — Transaction Builder API Tests

Tests for the `TransactionBuilder` covering transaction construction, gas configuration, and command generation.

- **Gas configuration**: single/multiple gas objects, gas price, gas budget, gas sponsor
- **Commands**: `transfer_objects`, `split_coins`, `merge_coins`, `move_call`, `publish`, `upgrade`, `make_move_vec`
- **`send_coins`**: single coin with amount, multiple coins with merge (uses turbofish for type inference)
- **Error cases**: missing gas objects, missing gas price, gas station without data

### `src/types/move_arg.rs` — ULEB128 Encoding & Collection Serialization Tests

Tests for the BCS serialization logic used in Move call arguments.

- **`u32_as_uleb128()`**: zero, single-byte max (127), two-byte (128), multi-byte (300, 16384), max u32 (5-byte encoding)
- **`MoveArgCollection` for `Option<T>`**: `None` encodes as `[0]`, `Some` encodes with `[1]` prefix
- **`MoveArgCollection` for arrays**: length prefix + concatenated elements, empty array
- **`MoveArgCollection` for `Vec<T>`**: length prefix + concatenated elements, empty vec
- **`MoveArg` impls**: `PureBytes` identity, `&str` BCS encoding (ULEB128 length + UTF-8), `String`/`&String` match `&str`

### `src/builder/gas_station.rs` — Version Parsing Tests

- **`GasStationVersion`**: parsing valid versions, major/minor/patch accessors, comparison ordering
- **Error handling**: invalid formats, non-numeric parts, leading zeros, extra parts

### `src/unresolved.rs` — Unresolved Transaction Type Tests

- **`UnresolvedTransaction`**: construction, sender, gas payment, expiration
- **`UnresolvedGasPayment`**: default values, partial fields, objects, budget, price, owner
- **`UnresolvedInputArgument`**: all variants, `is_mutable` for shared objects

### `src/error.rs` — Error Variant Tests

- **Display messages**: all 24 error variants
- **Constructors**: `Error::client()`, `Error::signature()` wrapping
- **From impls**: `base64ct::Error` conversion

---

## iota-sdk-graphql-client

### `src/query_types/mod.rs` — BigInt Conversion Tests

Tests for the `TryFrom<BigInt> for u64` conversion logic.

- **Valid conversions**: positive integer, zero, `u64::MAX`
- **Error cases**: overflow (`u64::MAX + 1`), negative value, non-numeric string, empty string

### `src/pagination.rs` — Page Utility Tests

Tests for pagination data structures and transformations.

- **`Page::map()`**: transforms data while preserving page_info, empty page mapping
- **`Page::is_empty()`**: true for empty, false for non-empty
- **`Page::into_parts()`**: decomposes into (PageInfo, Vec<T>)
- **`Page::new_empty()`**: default PageInfo values
- **`Direction`**: default is `Forward`
- **`PaginationFilter`**: default values

### `src/error.rs` — Error System Tests

- **Kind display**: all five variants
- **Constructors**: `from_error`, `from_message`, `empty_response_error`, `graphql_error`
- **From impls**: 9 error type conversions
- **`std::error::Error` trait**: `source()` chain behavior

### `src/faucet.rs` — Faucet Type Tests

- **FaucetRequest**: JSON serialization/deserialization
- **FaucetResponse**: successful/error response parsing
- **CoinInfo**: construction and field access
- **Edge cases**: empty coin lists, missing fields, null handling

### `src/streams.rs` — Stream Utility Tests

- **PageInfo**: construction, pagination state
- **Stream behavior**: single page, empty pages
- **Direction**: forward/backward pagination
