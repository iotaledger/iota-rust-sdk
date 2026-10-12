## [1.0.0-rc.1] - 2026-10-09

### 🚀 Features

- *(grpc)* View_function_call (#1291)
- *(grpc-types)* Re-export tonic, prost and prost-types (#1580)
- Re-export iota_types from every crate that names it publicly (#1581)

### 🐛 Bug Fixes

- *(iota-sdk-grpc-types)* Drop read-mask paths the Object message lacks (#1440)

### 🚜 Refactor

- Unify byte accessors as bytes()/into_bytes() (#1404)
- Align gRPC client method naming with the GraphQL client (#1408)
- *(types)* [**breaking**] Reduce the public surface of iota-sdk-types (#1473)
- *(grpc-client)* [**breaking**] Move the read masks and `skip_checks` to setters (#1555)
- *(grpc-client)* [**breaking**] Move the checkpoint streams' inputs to setters (#1557)
- *(grpc-types)* [**breaking**] Mark google.rpc messages and GrpcConversionError non-exhaustive (#1593)
- *(grpc-types)* [**breaking**] Seal MessageFields and mark MessageField non-exhaustive (#1594)
- [**breaking**] Replace bcs::Error in public signatures with iota_types::BcsError (#1591)

### 📚 Documentation

- *(grpc)* Say batch execution runs concurrently (#1641)

### ⚙️ Miscellaneous Tasks

- Add docs.rs metadata to the crates missing it (#1595)
- Use the README as the crate docs where it can carry them (#1602)
- Add crates.io and docs.rs badges to all published crate READMEs (#1642)

## [1.0.0-beta.1] - 2026-08-31

Initial Release
