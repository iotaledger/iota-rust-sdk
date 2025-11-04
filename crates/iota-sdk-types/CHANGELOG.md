## [0.0.1-alpha.1] - 2025-11-04

### 🚀 Features

- *(sui-sdk-types)* Object::as_struct getter
- Python bindings PoC (#40)
- *(graphql)* Update graphql schema and fix compatibility issues (#72)
- *(bindings)* Create `iota-sdk-ffi` crate for bindings (#42)
- *(ffi)* TypeTag and StructTag (#83)
- *(bindings)* Add `UserSignature` and dependent type impls (#74)
- *(bindings)* Add ObjectData, Owner, and ObjectType (#73)
- *(ffi)* `ChangeEpoch` and dependencies (#105)
- *(ffi)* `ExecutionTimeObservations` and dependencies (#107)
- Add typos CI (#132)
- Use `eyre` instead of `anyhow` (#218)
- Add new transaction builder (#206)
- Add support for IOTA-Names (#170)
- *(transaction-builder)* Set gas if none was provided (#270)
- *(transaction-builder)* Use PTBArgument trait for all builder calls (#276)
- *(makefile)* Add WASM rules for `iota-graphql-client` and `iota-transaction-builder` (#302)
- [**breaking**] Add TransactionData enum, rename Transaction to TransactionDataV1 (#246)
- *(types)* Add Transaction::{to/from bcs, base_64} (#303)
- *(*)* Use workspace deps (#337)
- *(crypto)* Add ability to create a private key from a mnemonic (#347)

### 🐛 Bug Fixes

- *(iota-graphql-client)* Independent compilation (#33)
- *(sdk-types)* Update SignedCheckpoints fixtures (#35)
- WASM compilation (#43)
- *(iota-sdk-types)* Fix numbers and typo (#226)
- *(*)* Replace deprecated `.as_slice` call  (#284)
- Remove unimplemented publish type (#321)

### 💼 Other

- Rename to_address to derive_address for all authenticators
- Enforce iss to be less than 255 bytes in length
- Provide an iterator for the valid zklogin addrsses
- Add doc comments for the top-level and Address
- Add some docs on objects (#94)
- Add some digest doc comments (#93)
- Add gas summary docs (#92)
- Documentation pass (#96)
- Add documentation to transaction types (#97)
- Expose ConsensusCommitPrologueV4 and fix ZkLoginClaim type name
- Add EndOfEpochTransactionKind::StoreExecutionTimeObservations (#105)
- Make ExecutionTimeObservation types public

### ⚙️ Miscellaneous Tasks

- Apply renames and clean upstream changes
- Fix build issues
- Rename branches and URLs
- Fix errors and add fixtures
- Update winnow to v0.7 (#95)
- Remove signature scheme for ed25519 addresses
- *(sdk, ffi)* Use macros to generate is/as/into methods (#112)
- *(examples)* Add `get_object` example (#147)
- *(ffi)* Add Display impls for types used by `get_object` examples (#201)
- *(examples)* Allow custom queries in bindings (#203)
- Reorganize some modules (#269)
- *(cleanup)* Use better names for default address constants (#283)
- *(graphql)* Make stream methods sync and add helpers (#275)
- *(ffi)* Add `signing_digest_hex()` function (#300)
- *(generate_ed25519_address)* Add `*PublicKey::to_flagged_bytes` and harmonize examples (#312)
- Rename crates to be uniform and organize dependencies better (#342)
- *(examples)* Add `TransactionBuilder` publish and upgrade example (#271)
- *(*)* Add remaining `StructTag` getters and ctors (#334)
- *(FFI)* Add ChangeEpochV3 to FFI
