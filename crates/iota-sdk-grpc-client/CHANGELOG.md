## [1.0.0-rc.1] - 2026-10-09

### 🚀 Features

- [**breaking**] Drop the read mask parameter from get_coins (#1441)
- *(grpc)* View_function_call (#1291)
- *(grpc)* Add `object_references` to the gRPC client (#1494)
- Add typed move_objects queries for GraphQL and gRPC (#1439)
- *(grpc-types)* Re-export tonic, prost and prost-types (#1580)
- Re-export iota_types from every crate that names it publicly (#1581)

### 🐛 Bug Fixes

- Use port 50051 for the localnet gRPC client (#1476)

### 🚜 Refactor

- Align gRPC client method naming with the GraphQL client (#1408)
- *(grpc)* [**breaking**] Reduce the public surface of iota-sdk-grpc-client (#1474)
- *(txn-builder)* [**breaking**] Reduce the public surface of iota-sdk-transaction-builder (#1475)
- Give the gRPC client a specific error name (#1479)
- *(types)* [**breaking**] Reduce the public surface of iota-sdk-types (#1473)
- [**breaking**] Rename `Client` to `GrpcClient` and `GraphQLClient` (#1503)
- *(grpc-client)* Generate list queries through a query-object macro (#1553)
- *(grpc-client)* [**breaking**] Move the list queries' optional inputs to setters (#1554)
- *(grpc-client)* [**breaking**] Move the read masks and `skip_checks` to setters (#1555)
- *(grpc-client)* [**breaking**] Move the optional inputs of checkpoints, execution, epoch and health to setters (#1556)
- *(grpc-client)* [**breaking**] Move the checkpoint streams' inputs to setters (#1557)
- *(grpc-client)* [**breaking**] Return request objects from the methods with nothing to configure (#1558)
- [**breaking**] Remove dead and inconsistent public API before 1.0 (#1574)
- *(grpc-types)* [**breaking**] Mark google.rpc messages and GrpcConversionError non-exhaustive (#1593)
- [**breaking**] Take plain values in the query-object setters (#1657)

### 📚 Documentation

- *(grpc)* Say batch execution runs concurrently (#1641)

### ⚙️ Miscellaneous Tasks

- [**breaking**] Update dependencies (#1346)
- Add docs.rs metadata to the crates missing it (#1595)
- Use the README as the crate docs where it can carry them (#1602)
- Add crates.io and docs.rs badges to all published crate READMEs (#1642)

## [1.0.0-beta.1] - 2026-08-31

Initial Release
