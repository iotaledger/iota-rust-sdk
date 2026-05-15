# iota-sdk-move-types

Rust representations of Move types used by the IOTA blockchain.

## Refreshing the BCS test fixtures

The roundtrip tests in `tests/fixture_roundtrip.rs` decode real on-chain
BCS bytes (committed under `tests/fixtures/*.bcs`) into the hand-curated
type mirrors and re-encode to assert byte-for-byte equality.

To refresh those fixtures against current chain state:

```bash
cargo run -p iota-sdk-move-types --example capture_fixtures
```

This queries the IOTA mainnet GraphQL endpoint, re-fetches each pinned
object (and dynamic field), and overwrites `tests/fixtures/*.bcs`. Use
`IOTA_NETWORK=testnet` / `IOTA_NETWORK=devnet` to capture against a
different network instead.

Most fixtures are pinned to specific object IDs and produce byte-for-byte
identical output across runs. The exceptions are `clock.bcs` (live
timestamp) and `iota_system_state_inner_v2.bcs` (changes at every epoch
boundary).

### Adding a new fixture

1. Add an entry to `FIXTURES` in `examples/capture_fixtures.rs`. Use
   `Source::TypeFilter("0x…::module::Type")` if you don't have an
   ObjectId yet.
2. Run the capture binary. For `Source::TypeFilter` entries, it prints
   the discovered ObjectId — copy it back into the fixture entry as a
   `Source::ObjectId(…)` pin so re-runs are stable.
3. Add a corresponding `#[test]` to `tests/fixture_roundtrip.rs`.
