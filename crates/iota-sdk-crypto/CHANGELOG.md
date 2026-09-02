## [1.0.0-beta.1] - 2026-08-31

### 🚀 Features

- *(iota-sdk-crypto)* Add generate_mnemonic() (#424)
- Make sure `iota-sdk` is wasm compatible (#476)
- Make public enums non_exhaustive (#487)
- Add Move Authenticator support (#442)
- *(iota-sdk-types)* Use camelCase in serialization (#545)
- *(scripts)* Add cargo sort script (#1061)
- *(iota-sdk-types)* Add passkey to multisig (#1075)
- Use `impl AsRef<[u8]>` for `from_bytes` methods (#1157)
- [**breaking**] `MultisigAggregatedSignature` changes (#1137)
- Add base64 helpers to the private key types (#1288)
- Add random() to the private key types (#1310)

### 🐛 Bug Fixes

- *(crates)* Feature flags for tests (#44)
- Correct wasm getrandom configuration for downstream consumers (#1193)
- *(iota-sdk-crypto)* Zeroize Bls12381PrivateKey on drop (#1374)

### 🚜 Refactor

- Remove deprecated zklogin variants from public signature enums (#1195)
- Use fastcrypto for ed25519, secp256r1 and secp256k1 crypto (#1248)
- *(iota-sdk-crypto)* Reuse MultisigAggregatedSignature::indices() in the verifier (#1327)
- [**breaking**] Rename generate to random_with and pair every random_with with random (#1344)
- [**breaking**] Implement IotaVerifier for public key types (#1345)

### ⚙️ Miscellaneous Tasks

- Fix broken links (#443)
- Bump to edition 2024 (#481)
- Some nits (#483)
- Use a portable version of blst (#1004)
- Add `IPHONEOS_DEPLOYMENT_TARGET` to ios builds (#1017)
- Remove ZkLogin and JWK (#1071)
- Remove `schemars` (#1073)
- Remove unused dependencies (#1143)
- Warn `uninlined_format_args` clippy lint (#1148)
- Standardize derive macro ordering across codebase (#1158)
- Document why SimpleKeypair wraps a private enum (#1202)
- Add multisig tests to iota-sdk-crypto and iota-sdk-types (#1237)
- Put doc comments before attributes (#1311)

## [0.0.1-alpha.1] - 2025-11-07

Initial Release
