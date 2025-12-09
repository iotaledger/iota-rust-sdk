# IOTA SDK FFI

Core type definitions for the IOTA blockchain.

This crate can generate bindings for various languages using [UniFFI](https://github.com/mozilla/uniffi-rs).

[IOTA](https://iota.org) is a next-generation smart contract platform with high throughput, low latency, and an asset-oriented programming model powered by the Move programming language. This crate provides type definitions for working with the data that makes up the IOTA blockchain.

## BCS

[BCS](https://docs.rs/bcs) is the serialization format used to represent the state of the blockchain and is used extensively throughout the IOTA ecosystem. In particular the BCS format is leveraged because it _"guarantees canonical serialization, meaning that for any given data type, there is a one-to-one correspondence between in-memory values and valid byte representations."_

One benefit of this property of having a canonical serialized representation is to allow different entities in the ecosystem to all agree on how a particular type should be interpreted and more importantly define a deterministic representation for hashing and signing.

This library strives to guarantee that the types defined are fully BCS-compatible with the data that the network produces. The one caveat to this would be that as the IOTA protocol evolves, new type variants are added and older versions of this library may not support those newly added variants. The expectation is that the most recent release of this library will support new variants and types as they are released to IOTA's `testnet` network.

See the documentation for the various types defined by this crate for a specification of their BCS serialized representation which will be defined using ABNF notation as described by [RFC-5234](https://datatracker.ietf.org/doc/html/rfc5234). In addition to the format itself, some types have an extra layer of verification and may impose additional restrictions on valid byte representations above and beyond those already provided by BCS. In these instances the documentation for those types will clearly specify these additional restrictions.

Here are some common rules:

```text
; --- BCS Value ---
bcs-value           = bcs-struct / bcs-enum / bcs-length-prefixed / bcs-fixed-length
bcs-length-prefixed = bytes / string / vector / option
bcs-fixed-length    = u8 / u16 / u32 / u64 / u128 /
                      i8 / i16 / i32 / i64 / i128 /
                      boolean
bcs-struct          = *bcs-value                ; Sequence of serialized fields
bcs-enum            = uleb128-index bcs-value   ; Enum index and associated value
; --- Length-prefixed types ---
bytes           = uleb128 *OCTET          ; Raw bytes of the specified length
string          = uleb128 *OCTET          ; valid utf8 string of the specified length
vector          = uleb128 *bcs-value      ; Length-prefixed list of values
option          = %x00 / (%x01 bcs-value) ; optional value
; --- Fixed-length types ---
u8          = OCTET                     ; 1-byte unsigned integer
u16         = 2OCTET                    ; 2-byte unsigned integer, little-endian
u32         = 4OCTET                    ; 4-byte unsigned integer, little-endian
u64         = 8OCTET                    ; 8-byte unsigned integer, little-endian
u128        = 16OCTET                   ; 16-byte unsigned integer, little-endian
i8          = OCTET                     ; 1-byte signed integer
i16         = 2OCTET                    ; 2-byte signed integer, little-endian
i32         = 4OCTET                    ; 4-byte signed integer, little-endian
i64         = 8OCTET                    ; 8-byte signed integer, little-endian
i128        = 16OCTET                   ; 16-byte signed integer, little-endian
boolean     = %x00 / %x01               ; Boolean: 0 = false, 1 = true
array       = *(bcs-value)              ; Fixed-length array
; --- ULEB128 definition ---
uleb128         = 1*5uleb128-byte       ; Variable-length ULEB128 encoding
uleb128-byte    = %x00-7F / %x80-FF     ; ULEB128 continuation rules
uleb128-index   = uleb128               ; ULEB128-encoded variant index
```

## Transaction Builder

This crate contains the
[TransactionBuilder](./src/transaction_builder/mod.rs), which allows
for construction of Programmable Transactions which can be executed on the
IOTA network.

### Methods

The following methods are available:

#### Commands

Each command method adds one or more commands to the final transaction. Some commands have optional follow-up methods. Most command results can be named, which allows them to be used later in the transaction via the `PTBArgument::Res` variant. When a single name is provided, the result will be named, and when a list of names is provided, the names will be used for the individual nested results.

- `move_call`: Call a move function.
- `send_iota`: Send IOTA coins to a recipient address.
- `send_coins`: Send coins of any type to a recipient address.
- `merge_coins`: Merge a list of coins into a single primary coin.
- `split_coins`: Split a coin into coins of various amounts.
- `transfer_objects`: Send objects to a recipient address.
- `publish`: Publish a move package.
- `upgrade`: Upgrade a move package.
- `make_move_vec`: Create a move `vector`.

#### Metadata

These methods set various metadata which may be needed for the execution.

- `gas`: Add a gas coin to pay for the execution.
- `gas_coins`: Add gas coins to pay for the execution.
- `gas_budget`: Set the maximum gas budget to spend.
- `gas_price`: Set the gas price.
- `sponsor`: Set the gas sponsor address.
- `gas_station_sponsor`: Set the gas station URL. See [Gas Station](#gas-station) for more info.
- `expiration`: Set the transaction expiration epoch.

### Finalization and Execution

There are several ways to finish the builder. First, the `TransactionBuilder::finish` method can be used to return the resulting `Transaction`, which can be manually serialized, executed, etc.

Additionally, the builder can directly `TransactionBuilder::dry_run` or `TransactionBuilder::execute` the transaction.

When the transaction is resolved, the builder will try to ensure a valid state by de-duplicating and converting appropriate inputs into references to the gas coin. This means that the same input can be passed multiple times and the final transaction will only contain one instance. However, in some cases an invalid state can still be reached. For instance, if a coin is used both for gas and as part of a group of coins, i.e. when transferring objects, the transaction can not possibly be valid.

#### Defaults

The builder can set some values by default. The
following are the default behaviors for each metadata value.

- Gas: One page of coins owned by the sender.
- Gas Budget: A dry run will be used to estimate.
- Gas Price: The current reference gas price.

### Gas Station

The Transaction Builder supports executing via a [Gas Station](https://github.com/iotaledger/gas-station). To do so, the URL, duration, and headers must be provided via `TransactionBuilder::gas_station_sponsor`.

By default the request will contain the header `Content-Type: application/json` When this data has been set, calling `TransactionBuilder::execute` will request gas from and send the resulting transaction to this endpoint instead of using the GraphQL client.

## Supported languages

- [Go](../../bindings/go)
- [Kotlin](../../bindings/kotlin)
- [Python](../../bindings/python)
