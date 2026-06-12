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

## Compiled Move packages (`src/packages_compiled/`, not committed)

The `move_shape_compare` test `include_bytes!`s the compiled bytecode
blobs of the four packages above (`move-stdlib`, `iota-framework`,
`iota-system`, `stardust`) plus `published_api.txt`, the upstream
public-API manifest (filtered to `public struct` / `public enum`
records). It parses each Move struct/enum out of the bytecode and
verifies that the corresponding Rust mirror's wire layout matches.

These artifacts are **not committed** — they are fetched from
`crates/iota-framework/` in the [iota monorepo] into the gitignored
`src/packages_compiled/` directory, at the monorepo commit pinned by the
`move-binary-format` dev-dependency rev in this crate's `Cargo.toml` (the
single source of truth: the parser must match the blobs it parses). The
`make` targets that compile tests (`test`, `clippy`, `wasm` — both
crate-level and repo-root) fetch them automatically when they are missing
or were fetched at a different rev than the pin, so CI and local runs
always test against the exact same bytes.
If you bypass `make` (e.g. plain `cargo nextest run`) on a fresh
checkout, the build fails with a "couldn't read …packages_compiled/…"
error — fetch first:

```bash
make update-compiled-packages              # at the pinned rev (default)
make update-compiled-packages REF=develop  # a branch, e.g. to preview drift
make update-compiled-packages REF=<sha>    # a specific commit
```

The script needs `curl`, `cargo`, and `jq`.

### The completeness contract

The `registry_matches_published_api` test enforces that **every** public
`struct`/`enum` in the fetched `published_api.txt` has a registered Rust
mirror. The nightly drift workflow
(`.github/workflows/move_drift_nightly.yml`) diffs the manifest's type
surface at the pinned rev against upstream `develop` HEAD; a red nightly
means _upstream types changed and the mirror set is out of date_ — not
that the crate is broken. Pull requests are deliberately unaffected by
upstream drift: they keep testing against the pinned rev until the pin
moves.

The catch-up workflow when the nightly turns red:

1. Review the diff in the workflow log.
2. Add/update the Rust mirrors (and `entry!` registrations) it points at.
3. Bump the `move-binary-format` rev in this crate's `Cargo.toml` to the
   new monorepo SHA — this single rev pins both the parser and the
   artifact fetch.
4. Run `make update-compiled-packages` and `make test`, then open a PR —
   its CI validates the new mirrors against the new rev.

System packages change rarely, so the expected cadence is a small
catch-up PR a few times a year, with at most one day of detection delay.

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
