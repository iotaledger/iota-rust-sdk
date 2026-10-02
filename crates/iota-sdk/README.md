# iota-sdk

[![iota-sdk on crates.io](https://img.shields.io/crates/v/iota-sdk)](https://crates.io/crates/iota-sdk)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk)

A Rust SDK for integrating with the [IOTA blockchain](https://docs.iota.org/). This crate bundles
the SDK's libraries behind feature flags, so an application depends on one crate and compiles only
what it enables.

| Module                | Crate                                                                                   | Feature               |
| --------------------- | --------------------------------------------------------------------------------------- | --------------------- |
| `types`               | [`iota-sdk-types`](https://crates.io/crates/iota-sdk-types)                             | `types`               |
| `crypto`              | [`iota-sdk-crypto`](https://crates.io/crates/iota-sdk-crypto)                           | `crypto`              |
| `graphql_client`      | [`iota-sdk-graphql-client`](https://crates.io/crates/iota-sdk-graphql-client)           | `graphql`             |
| `transaction_builder` | [`iota-sdk-transaction-builder`](https://crates.io/crates/iota-sdk-transaction-builder) | `transaction-builder` |
| `grpc_client`         | [`iota-sdk-grpc-client`](https://crates.io/crates/iota-sdk-grpc-client)                 | `grpc`                |
| `grpc_types`          | [`iota-sdk-grpc-types`](https://crates.io/crates/iota-sdk-grpc-types)                   | `grpc`                |
| `move_types`          | [`iota-sdk-move-types`](https://crates.io/crates/iota-sdk-move-types)                   | `move-types`          |

## Example

Build, dry-run, sign and execute a transfer on a local network:

```rust,no_run
use eyre::Result;
use iota_sdk::{
    crypto::{IotaSigner, ed25519::Ed25519PrivateKey},
    graphql_client::{GraphQLClient, faucet::FaucetClient},
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let recipient =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let private_key = Ed25519PrivateKey::new([0; Ed25519PrivateKey::LENGTH]);
    let sender = private_key.public_key().derive_address();

    let client = GraphQLClient::new_localnet();
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sender, &client)
        .await?;

    let mut builder = client.transaction_builder(sender);
    builder.send_iota(recipient, 1_000u64);
    let tx = builder.finish().await?;

    let dry_run = client.dry_run_transaction(&tx, false).await?;
    if let Some(err) = dry_run.error {
        eyre::bail!("Dry run failed: {err}");
    }

    let signature = private_key.sign_transaction(&tx)?;
    let effects = client.execute_transaction(&[signature], &tx, None).await?;
    println!("Digest: {}", effects.digest());

    Ok(())
}
```

More examples, covering queries, Move calls, staking, multisig, gas sponsorship and the gRPC client,
are in the [`examples`](https://github.com/iotaledger/iota-rust-sdk/tree/develop/crates/iota-sdk/examples)
directory.

## Feature flags

The default features cover the transaction builder, the core types and all crypto schemes
except BLS12-381. GraphQL, gRPC, Move types and gas station sponsorship are opt-in.

| Feature                    | Default | Effect                                                                                    |
| -------------------------- | ------- | ----------------------------------------------------------------------------------------- |
| `types`                    | on      | `types` module                                                                            |
| `serde`                    | on      | serialization of the core types                                                           |
| `hash`                     | on      | hashing, needed to derive addresses and digests                                           |
| `rand`                     | on      | random generation of the core types and keys                                              |
| `proptest`                 | off     | `proptest` strategies for the core types                                                  |
| `crypto`                   | on      | `crypto` module, with the signing and verifying traits                                    |
| `ed25519`                  | on      | Ed25519 keys and signatures                                                               |
| `secp256k1`                | on      | Secp256k1 keys and signatures                                                             |
| `secp256r1`                | on      | Secp256r1 keys and signatures                                                             |
| `passkey`                  | on      | passkey signature verification                                                            |
| `bls12381`                 | off     | BLS12-381 keys and signatures                                                             |
| `pem`                      | on      | DER and PEM encoding of keys                                                              |
| `bech32`                   | on      | Bech32 encoding of private keys                                                           |
| `mnemonic`                 | on      | key derivation from mnemonic phrases                                                      |
| `transaction-builder`      | on      | `transaction_builder` module                                                              |
| `gas-station`              | off     | gas sponsorship through the [IOTA gas station](https://github.com/iotaledger/gas-station) |
| `graphql`                  | off     | `graphql_client` module                                                                   |
| `graphql-tls-ring`         | off     | `ring` as the GraphQL client's TLS crypto provider                                        |
| `graphql-tls-aws-lc`       | off     | `aws-lc-rs` as the GraphQL client's TLS crypto provider                                   |
| `graphql-tls-native-roots` | off     | trust the platform certificate store for GraphQL                                          |
| `graphql-tls-webpki-roots` | off     | trust the bundled Mozilla roots for GraphQL                                               |
| `grpc`                     | off     | `grpc_client` and `grpc_types` modules                                                    |
| `grpc-tls-ring`            | off     | `ring` as the gRPC client's TLS crypto provider                                           |
| `grpc-tls-aws-lc`          | off     | `aws-lc-rs` as the gRPC client's TLS crypto provider                                      |
| `grpc-tls-native-roots`    | off     | trust the platform certificate store for gRPC                                             |
| `grpc-tls-webpki-roots`    | off     | trust the bundled Mozilla roots for gRPC                                                  |
| `move-types`               | off     | `move_types` module, and typed Move object queries in the clients                         |

The `graphql-tls-*` and `grpc-tls-*` features map to the `tls-*` features
of [`iota-sdk-graphql-client`](https://crates.io/crates/iota-sdk-graphql-client) and
[`iota-sdk-grpc-client`](https://crates.io/crates/iota-sdk-grpc-client), whose READMEs describe how
they combine.

## License

This project is available under the terms of the
[Apache 2.0 license](https://github.com/iotaledger/iota-rust-sdk/blob/develop/LICENSE).
