# iota-sdk-move-types

Rust representations of Move types used by the IOTA blockchain.

Each top-level module mirrors one on-chain system package, with every Move
source module mirrored 1:1 as a Rust `pub mod`:

| Module        | Package ID | Move package                        |
| ------------- | ---------- | ----------------------------------- |
| `std`         | `0x1`      | Move standard library (move-stdlib) |
| `framework`   | `0x2`      | IOTA framework (iota-framework)     |
| `iota_system` | `0x3`      | IOTA system (iota-system)           |
| `stardust`    | `0x107a`   | Stardust migration (stardust)       |

The Move sources these mirror live in the [iota monorepo] under
`crates/iota-framework`.

[iota monorepo]: https://github.com/iotaledger/iota/tree/develop/crates/iota-framework

## Vendored Move packages (`src/packages_compiled/`)

`src/packages_compiled/` holds the compiled bytecode blobs for the four
packages above (`move-stdlib`, `iota-framework`, `iota-system`, `stardust`)
plus `published_api.txt`, the upstream public-API manifest. They are copied
verbatim from `crates/iota-framework/packages_compiled/` in the
[iota monorepo].

The blobs are read by the `move_shape_compare` test, which parses each Move
struct/enum out of the bytecode and verifies that the corresponding Rust
mirror's wire layout matches. `published_api.txt` (filtered to `public
struct` / `public enum` records) is diffed against upstream by the nightly
drift workflow (`.github/workflows/move_drift_nightly.yml`) to flag types
that were added, removed, or moved.

To refresh them against upstream (`develop` by default, or any branch):

```bash
make update-compiled-packages              # develop
make update-compiled-packages BRANCH=main  # a different branch
```

This is a manual step — no CI job regenerates these files.

### The completeness contract

The `registry_matches_published_api` test enforces that **every** public
`struct`/`enum` in the vendored `published_api.txt` has a registered Rust
mirror, and the nightly drift workflow keeps that manifest in sync with
upstream `develop`. Together they create a standing obligation: when
upstream publishes a new public type, the nightly turns red and stays red
until someone vendors the refreshed artifacts and lands the new mirror
(steps above). A red "Move Drift Nightly" therefore means _the mirror set
is out of date_, not that the crate is broken — already-released mirrors
keep decoding on-chain state just fine in the meantime. System packages
change rarely, so the expected cadence is a small catch-up PR a few times
a year, with at most one day of detection delay.

## Refreshing the BCS test fixtures

The roundtrip tests in `tests/fixture_roundtrip.rs` decode real on-chain
BCS bytes (committed under `tests/fixtures/*.bcs`) into the hand-curated
type mirrors and re-encode to assert byte-for-byte equality.

To refresh those fixtures against current chain state:

```bash
cargo run -p iota-sdk --example capture_move_type_fixtures
```

The capture binary lives in the `iota-sdk` crate (it needs the GraphQL
client), but it writes back into this crate's `tests/fixtures/`.

This queries the IOTA mainnet GraphQL endpoint, re-fetches each pinned
object (and dynamic field), and overwrites `tests/fixtures/*.bcs`. Use
`IOTA_NETWORK=testnet` / `IOTA_NETWORK=devnet` to capture against a
different network instead.

Most fixtures are pinned to specific object IDs and produce byte-for-byte
identical output across runs. The exceptions are `clock.bcs` (live
timestamp) and `iota_system_state_inner_v2.bcs` (changes at every epoch
boundary).

### Adding a new fixture

1. Add an entry to `FIXTURES` in
   `crates/iota-sdk/examples/capture_move_type_fixtures.rs`. Use
   `Source::TypeFilter("0x…::module::Type")` if you don't have an
   ObjectId yet.
2. Run the capture binary. For `Source::TypeFilter` entries, it prints
   the discovered ObjectId — copy it back into the fixture entry as a
   `Source::ObjectId(…)` pin so re-runs are stable.
3. Add a corresponding `#[test]` to `tests/fixture_roundtrip.rs`.
