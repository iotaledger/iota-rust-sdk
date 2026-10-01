# iota-sdk-transaction-builder

[![iota-sdk-transaction-builder on crates.io](https://img.shields.io/crates/v/iota-sdk-transaction-builder)](https://crates.io/crates/iota-sdk-transaction-builder)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-transaction-builder)

This crate contains the `TransactionBuilder`, which allows for simple construction of Programmable
Transactions which can be executed on the IOTA network.

The builder is designed to allow for a lot of flexibility while also reducing the necessary
boilerplate code. It uses a type-state pattern to ensure the proper flow through the various
functions. It is chainable via mutable references.

## Online vs. Offline Builder

The Transaction Builder can be used with or without a client implementing
`TransactionBuilderLedgerClient`. When one is provided via the `with_client` method, the resulting
builder will use it to find and validate provided IDs. A ledger-only client can build transactions
with an explicit gas budget via `finish_with_budget`.

Clients that also implement `TransactionBuilderSimulationClient` enable `dry_run` and `finish` with
automatic gas budget estimation.

Clients that additionally implement `TransactionBuilderExecutionClient` enable
`execute`.

Ready-made clients ship with the
[`iota-sdk-graphql-client`](https://crates.io/crates/iota-sdk-graphql-client) and
[`iota-sdk-grpc-client`](https://crates.io/crates/iota-sdk-grpc-client) crates. To back the builder
with another transport, implement the three client traits; `TransactionBuilderClient` is then
implemented automatically. `objects_by_id` (one request per object) and `protocol_config` have
default implementations worth overriding when your transport can batch requests or fetch the real
protocol configuration.

### Example with Client Resolution

```rust,ignore
use std::str::FromStr;

use iota_sdk_transaction_builder::TransactionBuilder;
use iota_sdk_types::{Address, ObjectId, Transaction};

let sender =
    Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
let to_address =
    Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

let mut builder = TransactionBuilder::new(sender).with_client(client);

let coin =
    ObjectId::from_str("0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2")?;

builder.send_coins([coin], to_address, 50000000000u64);

let txn: Transaction = builder.finish().await?;
```

### Example without Client Resolution

```rust,ignore
use std::str::FromStr;

use iota_sdk_transaction_builder::TransactionBuilder;
use iota_sdk_types::{Address, ObjectDigest, ObjectId, ObjectReference, Transaction, Version};

let sender =
    Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
let to_address =
    Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

let mut builder = TransactionBuilder::new(sender);

let coin = ObjectReference {
    object_id: ObjectId::from_str(
        "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2",
    )?,
    digest: ObjectDigest::from_str("hSAGU3ZwDwxptd17ZK1QPDdJLhvPMfpSxe1p892GFVn")?,
    version: Version::from_u64(545110774),
};
let gas_coin = ObjectReference {
    object_id: ObjectId::from_str(
        "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
    )?,
    digest: ObjectDigest::from_str("8ahH5RXFnK1jttQEWTypYX7MRzLuQDEXk7fhMHCyZekX")?,
    version: Version::from_u64(473053810),
};

builder
    .send_coins([coin], to_address, 50000000000u64)
    .gas([gas_coin])
    .gas_budget(1000000000)
    .gas_price(100);

let txn: Transaction = builder.finish()?;
```

NOTE: It is possible to provide an `ObjectId` to an offline client builder, but this will cause
the builder to fail when calling `finish`.

## Methods

There are three kinds of methods available:

### Commands

Each command method adds one or more commands to the final transaction. Some commands have optional
follow-up methods. All command results can be assigned a name via `assign`. Assigning a name to a
command allows them to be used later in the transaction via the `assigned` method.

- `move_call`: Call a move function.
  - `arguments`: Add arguments to the move call.
  - `generics`: Add generic types to the move call using types that implement `MoveType`.
  - `type_tags`: Add generic types directly using the `TypeTag`.
- `send_iota`: Send IOTA coins to a recipient address.
- `send_coins`: Send coins of any type to a recipient address.
- `pay`: Send coins of any type to several recipients, each paired with the amount to send.
- `pay_iota`: Send IOTA coins from the gas coin to several recipients.
- `merge_coins`: Merge a list of coins into a single primary coin.
- `split_coins`: Split a coin into coins of various amounts.
- `transfer_objects`: Send objects to a recipient address.
- `publish_package`: Publish a move package.
  - `package_id`: Name the package ID returned by the publish call.
- `upgrade`: Upgrade a move package.
- `make_move_vec`: Create a move `vector`.

### Metadata

These methods set various metadata which may be needed for the execution.

- `gas`: Add gas coins to pay for the execution.
- `gas_refs`: Add gas coins that the caller has already resolved to references.
- `gas_budget`: Set the maximum gas budget to spend.
- `gas_price`: Set the gas price.
- `sponsor`: Set the gas sponsor address.
- `expiration`: Set the transaction expiration epoch.

### Other

Many other methods exist, either to get data or allow for development on top of the builder.
Typically, these methods should not be needed, but they are made available for special
circumstances: `apply_argument`, `apply_arguments`, `input`, `pure_bytes`, `pure`, `command` and
`assigned_command`.

## Finalization and Execution

There are several ways to finish the builder. First, the `finish` method can be used to return the
resulting `Transaction`, which can be manually serialized, executed, etc. On a client without
simulation support, use `finish_with_budget` instead and provide the gas budget explicitly.

Additionally, when a client is provided, the builder can directly `dry_run` or `execute` the
transaction.

When the gas payment is decided elsewhere, `finish_kind` returns just the `TransactionKind`: the
inputs are resolved with the client, but no gas coins are selected, no budget is estimated and no
gas price is fetched.

When the transaction is resolved, the builder will try to ensure a valid state by de-duplicating
and converting appropriate inputs into references to the gas coin. This means that the same input
can be passed multiple times and the final transaction will only contain one instance. However, in
some cases an invalid state can still be reached. For instance, if a coin is used both for gas and
as part of a group of coins, i.e. when transferring objects, the transaction can not possibly be
valid.

### Defaults

When a client is provided, the builder can set some values by default. The following are the
default behaviors for each metadata value.

- Gas: One page of coins owned by the sender.
- Gas Budget: A dry run will be used to estimate.
- Gas Price: The current reference gas price.

## Gas Sponsorship

A transaction's gas can be paid by someone other than its sender, in two ways depending on who
holds the sponsor's key.

When you hold it, set the sponsor's address with `sponsor` — the gas coins are drawn from it — and
call `execute_with_sponsor_signer`, which signs as both parties and submits through the client.

When a service holds it, pass a `GasSponsor` to `execute_with_gas_sponsor`. It supplies the whole
gas payment and submits the transaction itself, so the sender's own coins are never looked up;
setting gas coins or a `sponsor` address on the same builder is rejected.

`GasStation` implements `GasSponsor` for the [IOTA gas station](https://github.com/iotaledger/gas-station)
and is enabled by the `gas-station` feature. A station is configured once — with its URL and,
typically, an authorization header — and reused for any number of transactions:

```rust,ignore
use iota_sdk_transaction_builder::{GasStation, HeaderValue, header::AUTHORIZATION};

let station = GasStation::builder("http://0.0.0.0:9527".parse()?)
    .header(AUTHORIZATION, HeaderValue::from_static("Bearer token"))
    .build();
```

Pass `http_client` to control timeouts, proxies or TLS roots; otherwise reqwest's defaults are
used. Requests carry `Content-Type: application/json` unless a header overrides it.

Implement `GasSponsor` yourself to sponsor through a service this crate does not ship.

## Traits and Helpers

This crate provides several traits which enable the functionality of the builder. Often, when
providing arguments, functions will accept either a single `PTBArgument` or a `PTBArgumentList`.

`PTBArgument` is implemented for any type implementing `MoveArg` as well as:

- `unresolved::Argument`: Arguments returned by various builder functions. Distinct from
  `iota_sdk_types::Argument`, which cannot be used.
- `Input`: A resolved input.
- `ObjectId`: An object's ID. Can only be used when a client is provided. This will be assumed
  immutable or owned.
- `ObjectReference`: An object's reference. This will be assumed immutable or owned.
- `Assigned`: A reference to the result of a previous assigned command, set with `assign`.
- `Shared`: Allows specifying shared immutable move objects.
- `SharedMut`: Allows specifying shared mutable move objects.
- `Receiving`: Allows specifying receiving move objects.

`PTBArgumentList` is implemented for collection types, and represents a set of arguments. For move
calls, this enables tuples of rust values to represent the parameters defined in the smart
contract. For calls like `merge_coins`, this can represent a list of coins.

`MoveArg` represents types that can be serialized and provided to the transaction as pure bytes.

`MoveType` defines the type tag for a rust type, so that it can be used for generic arguments.

### Example

The following function is defined in move in `vec_map`:

```move
public fun from_keys_values<K: copy, V>(mut keys: vector<K>, mut values: vector<V>): VecMap<K, V>
```

```rust,ignore
builder
    .move_call(Address::TWO, "vec_map", "from_keys_values")
    .generics::<(Address, u64)>()
    .arguments(([address1, address2], [10000000u64, 20000000u64]));
```

### Custom Type

In order to use a custom type, implement `MoveType` and `MoveArg`.

```rust,ignore
use std::str::FromStr;

use iota_sdk_transaction_builder::types::{MoveArg, MoveType, PureBytes};
use iota_sdk_types::TypeTag;

#[derive(serde::Serialize)]
struct MyStruct {
    val1: String,
    val2: u64,
}

impl MoveType for MyStruct {
    fn type_tag() -> TypeTag {
        TypeTag::from_str("0x0::my_module::MyStruct").unwrap()
    }
}

impl MoveArg for MyStruct {
    fn pure_bytes(self) -> PureBytes {
        PureBytes(bcs::to_bytes(&self).unwrap())
    }
}
```
