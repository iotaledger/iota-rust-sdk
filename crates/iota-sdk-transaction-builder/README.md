# iota-sdk-transaction-builder

A fluent API for constructing Programmable Transactions that can be executed on the IOTA network.
The builder uses a type-state pattern to ensure the proper flow through the various functions and
is chainable via mutable references.

## Online vs. offline building

The builder works with or without a client implementing `TransactionBuilderClient`. When one is
provided via `with_client`, the resulting builder uses it to resolve and validate provided IDs
(e.g. looking up object references and gas data from the network). Without a client, all inputs —
object references, gas payment, gas price, and budget — must be supplied manually.

## Custom client implementations

`TransactionBuilderClient` is a plain trait, so any transport can back the builder by implementing
it: fetching objects, the reference gas price, protocol configuration, and executing or dry-running
transactions. Ready-made implementations ship with the
[`iota-sdk-graphql-client`](https://crates.io/crates/iota-sdk-graphql-client) and
[`iota-sdk-grpc-client`](https://crates.io/crates/iota-sdk-grpc-client) crates.

To write your own, pick an `Error` and `DryRunResult` type and implement the required methods;
`objects_by_id` (per-object loop) and `protocol_config` (defaults) have default implementations
worth overriding when your transport can batch requests or fetch the real protocol configuration.

## Example

```rust,ignore
use iota_sdk_transaction_builder::TransactionBuilder;
use iota_sdk_types::{Address, ObjectId, Transaction};

let mut builder = TransactionBuilder::new(sender).with_client(client);
builder.send_coins([coin], to_address, 50_000_000_000u64);
let txn: Transaction = builder.finish().await?;
```

See the crate documentation for complete online and offline examples.
