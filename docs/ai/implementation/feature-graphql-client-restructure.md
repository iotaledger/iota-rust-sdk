---
phase: implementation
title: "Implementation Guide: GraphQL Client Restructure"
description: "Code structure and conventions for the restructured query_types module"
---

# Implementation Guide

## Development Setup

```bash
cd crates/iota-sdk-graphql-client
cargo check   # Verify compilation
cargo clippy --all-features --all-targets  # Lint
```

## Code Structure (After Refactor)

```
src/query_types/
├── mod.rs              # Barrel: mod + pub use + schema + deprecated aliases
├── common.rs           # Scalars, shared fragments, PageInfo
├── active_validators.rs
├── balance.rs
├── chain.rs
├── checkpoint.rs
├── coin.rs
├── dry_run.rs
├── dynamic_fields.rs
├── epoch.rs
├── events.rs
├── iota_names.rs
├── move_view_call.rs
├── normalized_move/
│   ├── mod.rs
│   ├── function.rs
│   └── module.rs
├── object.rs
├── packages.rs
├── protocol_config.rs
├── service_config.rs
└── transaction.rs      # Includes execute_tx types (merged)
```

## Naming Conventions

| Concept | Convention | Example |
|---------|-----------|---------|
| Top-level query struct | `{Entity}Query` | `BalanceQuery` |
| Query variables | `{Entity}QueryArgs` | `BalanceQueryArgs` |
| Paginated query struct | `{Entities}Query` | `TransactionBlocksQuery` |
| Paginated query variables | `{Entities}QueryArgs` | `TransactionBlocksQueryArgs` |
| GraphQL fragment | `{TypeName}` | `Epoch`, `Checkpoint` |
| Connection type | `{TypeName}Connection` | `TransactionBlockConnection` |
| Filter input | `{TypeName}Filter` | `TransactionBlockFilter` |

## File Structure Convention

Each file in `query_types/` follows:

1. **Copyright header**
2. **Module doc comment** (`//!` — one descriptive line summarizing the file's domain)
3. **Imports**
4. **Queries** section (with `// ===` header)
5. **Query Args** section
6. **Types** section
7. **Conversions** section (optional, for `TryFrom`/`Into` impls)

> Files with a single merged domain (e.g., `transaction.rs`) may have multiple named sections within Steps 4–7.
