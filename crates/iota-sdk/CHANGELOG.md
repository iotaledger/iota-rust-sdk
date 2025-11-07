## [3.0.0-alpha.1] - 2025-11-07

### 🚀 Features

- Add new transaction builder (#206)
- *(transaction-builder)* Use PTBArgument trait for all builder calls (#276)
- *(types)* Add Transaction::{to/from bcs, base_64} (#303)
- Add tx_command_results example (#274)
- *(tx-builder)* Improve `TransactionBuilder::make_move_vec()` docs (#336)
- *(*)* Use workspace deps (#337)
- *(transaction-builder)* Add high level stake and unstake fns (#345)
- *(graphql)* Allow waiting for finalization in client (#349)
- *(crypto)* Add ability to create a private key from a mnemonic (#347)
- *(tx-builder)* Unify gas methods and improve/update docs  (#335)
- Add get-transaction examples (#361)
- Add json_query examples (#373)
- *(transaction-builder)* Make client in builder extensible and passable by ref (#315)

### 🐛 Bug Fixes

- *(CI)* Make pre-publish CI create a PR (#367)

### ⚙️ Miscellaneous Tasks

- Add `iota-sdk` crate for publishing (#240)
- Move examples to iota-sdk wrapper crate (#305)
- *(cleanup)* Use better names for default address constants (#283)
- *(graphql)* Make stream methods sync and add helpers (#275)
- *(ffi)* Add `signing_digest_hex()` function (#300)
- *(examples)* Add coin-type to coin_balances (#327)
- *(generate_ed25519_address)* Add `*PublicKey::to_flagged_bytes` and harmonize examples (#312)
- Rename crates to be uniform and organize dependencies better (#342)
- *(examples)* Add `TransactionBuilder` publish and upgrade example (#271)
- *(*)* Add remaining `StructTag` getters and ctors (#334)
