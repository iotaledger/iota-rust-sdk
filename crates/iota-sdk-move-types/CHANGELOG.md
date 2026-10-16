## [1.0.0-rc.1] - 2026-10-09

### 🚀 Features

- Add typed move_objects queries for GraphQL and gRPC (#1439)
- Re-export iota_types from every crate that names it publicly (#1581)

### 🐛 Bug Fixes

- *(graphql-client)* [**breaking**] Return a GraphQLResult from the network constructors (#1638)

### 🚜 Refactor

- [**breaking**] Rename `Client` to `GrpcClient` and `GraphQLClient` (#1503)
- [**breaking**] Remove dead and inconsistent public API before 1.0 (#1574)
- *(graphql-client)* [**breaking**] Return query objects from the paginated methods (#1569)
- *(graphql-client)* [**breaking**] Return query objects from the methods with optional inputs (#1575)
- [**breaking**] Replace bcs::Error in public signatures with iota_types::BcsError (#1591)
- [**breaking**] Share MoveType between move-types and the transaction builder (#1544)
- *(iota-sdk-move-types)* [**breaking**] Return X<()> from try_from_object_with_type on phantom mirrors (#1630)
- *(graphql-client)* [**breaking**] Take SDK types instead of strings (#1654)

### ⚙️ Miscellaneous Tasks

- Bring BCS ABNF doc comments in line with the generated schema (#1485)
- [**breaking**] Update dependencies (#1346)
- Add docs.rs metadata to the crates missing it (#1595)
- Add crates.io and docs.rs badges to all published crate READMEs (#1642)

## [1.0.0-beta.1] - 2026-08-31

Initial Release
