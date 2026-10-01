# iota-sdk-graphql-client

[![iota-sdk-graphql-client on crates.io](https://img.shields.io/crates/v/iota-sdk-graphql-client)](https://crates.io/crates/iota-sdk-graphql-client)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-graphql-client)

The IOTA GraphQL client is a client for interacting with the IOTA blockchain via GraphQL.
It provides a set of APIs for querying the blockchain for information such as chain identifier,
reference gas price, protocol configuration, service configuration, checkpoint, epoch,
executing transactions and more.

# Design Principles

1. **Type Safety**: The client uses the `cynic` library to generate types from the schema. This ensures that the queries are type-safe.
1. **Convenience**: The client provides a set of APIs for common queries such as chain identifier, reference gas price, protocol configuration, service configuration, checkpoint, epoch, executing transactions and more.
1. **Custom Queries**: The client provides a way to run custom queries using the `cynic` library.

# TLS

HTTPS is verified with `rustls`. Every axis has a default, so reaching the public networks needs no setup.

| Feature            | Default | Effect                                                                                                                                                                                                                                                                                                       |
| ------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tls-ring`         | on      | `ring` as the `rustls` crypto provider                                                                                                                                                                                                                                                                       |
| `tls-aws-lc`       | off     | `aws-lc-rs` instead; builds a C library, so it needs a C toolchain and `libclang` on targets without prebuilt bindings. `tls-ring` wins if both are on — `rustls` cannot be asked to choose.                                                                                                                 |
| neither provider   | —       | HTTP-only: `reqwest` is built without TLS, nothing verifies certificates, the root features below are ignored, and `Client::new` rejects an `https` or `wss` address rather than letting the request fail later. The build to use against a localnet.                                                        |
| `tls-native-roots` | on      | trust the platform store. Alone it changes nothing, since that is already `reqwest`'s default; its effect is to merge rather than replace when `tls-webpki-roots` is also on.                                                                                                                                |
| `tls-webpki-roots` | on      | add the bundled Mozilla roots, merged into the platform store when `tls-native-roots` is also on. Merging is a union, not a fallback: a CA the platform has deliberately distrusted is still accepted if the bundled set carries it. Turn off `tls-native-roots` if the bundled set should be authoritative. |
| neither roots      | —       | the platform store alone. `reqwest` constructs its verifier eagerly, before it knows whether a request uses TLS, so on Linux an empty system store fails the build even for plain-HTTP use — which is what the bundled roots otherwise prevent.                                                              |

Android always uses the bundled roots alone: it cannot merge the two, and its
platform verifier aborts the process unless the application performs a JNI
handshake this crate cannot do on its behalf. On wasm32 none of this applies —
the browser owns certificate verification.

## Bringing your own client

`Client::new_with_reqwest_client` takes a `reqwest::Client` you built yourself, for
pinning a certificate set, choosing a different TLS backend, or setting proxies
and timeouts. Because this crate selects the rustls crypto provider itself
rather than letting `reqwest` hard-wire aws-lc-rs, a build with a provider
feature panics unless a provider has been installed for the process. Install one
first — the first caller wins, so this is a no-op if the application has already
chosen:

```rust, ignore
use iota_graphql_client::GraphQLClient;

rustls::crypto::ring::default_provider().install_default().ok();

let http = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(5))
    .build()?;
let client = Client::new_with_reqwest_client("https://graphql.testnet.iota.cafe", http)?;
```

Such a client has none of this crate's own defaults: no user agent (`USER_AGENT`
is exported if you want it) and no bundled roots, so it trusts whatever your
`reqwest` features chose. An HTTP-only build has nothing to install, since
`reqwest` is built without TLS and its builder needs no provider; reaching
`https://` from one means enabling a provider feature here, or turning on
`reqwest`'s TLS in your own manifest.

# Usage

## Connecting to a GraphQL server

Instantiate a client with [`GraphQLClient::new(server: &str)`] or use one of the predefined functions for different networks [`GraphQLClient`].

```rust, ignore
use iota_graphql_client::GraphQLClient;
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {

   // Connect to the mainnet GraphQL server
   let client = GraphQLClient::new_mainnet();
   let chain_id = client.chain_id().await?;
   println!("{:?}", chain_id);

   Ok(())
}
```

## Requesting gas from the faucet

The client provides an API to request gas from the faucet. The `request_and_wait` function sends a request to the faucet and waits until the transaction is confirmed. The function returns the transaction details if the request is successful.

### Example for a local network.

The testnet and devnet faucets are only available through the web interface, so `FaucetClient` can only be used with a local or custom faucet service.

```rust, ignore
use iota_graphql_client::faucet::FaucetClient;
use iota_types::Address;

use eyre::Result;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    let address = Address::from_str("IOTA_ADDRESS_HERE")?;
    // Request gas from the faucet and wait until a coin is received
    let faucet = FaucetClient::new_localnet().request_and_wait(address).await?;
    if let Some(resp) = faucet {
        let coins = resp.sent;
        for coin in coins {
            println!("coin: {:?}", coin);
        }
    }

    Ok(())
}
```

### Example for custom faucet service.

Note that this `FaucetClient` is explicitly designed to work with two endpoints: `v1/gas`, and `v1/status`. When passing in the custom faucet URL, skip the final endpoint and only pass in the top-level url (e.g., `http://localhost:9123`).

```rust, ignore
use iota_graphql_client::faucet::FaucetClient;
use iota_types::Address;

use eyre::Result;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    let address = Address::from_str("IOTA_ADDRESS_HERE")?;
    // Request gas from the faucet and wait until a coin is received
    let faucet = FaucetClient::new("http://localhost:9123").request_and_wait(address).await?;
    if let Some(resp) = faucet {
        let coins = resp.sent;
        for coin in coins {
            println!("coin: {:?}", coin);
        }
    }
    Ok(())
}
```

## Custom Queries

There are several options for running custom queries.

1. Use a GraphQL client library of your choosing.
2. Use the [cynic's web generator](https://generator.cynic-rs.dev/) that accepts as input the schema and generates the query types.
3. Use the [cynic's CLI](https://github.com/obmarg/cynic/tree/main/cynic-cli) and use the `cynic querygen` command to generate the query types.

Below is an example that uses the `cynic querygen` CLI to generate the query types from the schema and the following query:

```bash
cynic querygen --schema rpc.graphql --query custom_query.graphql
```

where `custom_query.graphql` contains the following query:

```graphql
query CustomQuery($id: UInt53) {
  epoch(id: $id) {
    referenceGasPrice
    totalGasFees
    totalCheckpoints
    totalTransactions
  }
}
```

When using `cynic` and `iota-sdk-graphql-client`, you will need to register the schema by calling `iota-sdk-graphql-client-build::register_schema` in a `build.rs` file. See [iota-sdk-graphql-client-build](https://github.com/iotaledger/iota-rust-sdk/tree/develop/crates/iota-sdk-graphql-client-build) for more information.

The generated query types are defined below. Note that the `id` variable is optional (to make it mandatory change the schema to $id: Uint53! -- note the ! character which indicates a mandatory field). That means that if the `id` variable is not provided, the query will return the data for the last known epoch.
Note that instead of using `Uint53`, the scalar is mapped to `u64` in the library using `impl_scalar(u64, schema::Uint53)`, thus all references to `Uint53` in the schema are replaced with `u64` in the code below.

```rust, ignore
#[derive(cynic::QueryVariables, Debug)]
pub struct CustomQueryVariables {
    pub id: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "SCHEMA_NAME_HERE", graphql_type = "Query", variables = "CustomQueryVariables")]
pub struct CustomQuery {
    #[arguments(id: $id)]
    pub epoch: Option<Epoch>,
}

#[derive(cynic::QueryFragment, Debug)]
pub struct Epoch {
    pub epoch_id: u64,
    pub reference_gas_price: Option<BigInt>,
    pub total_gas_fees: Option<BigInt>,
    pub total_checkpoints: Option<u64>,
    pub total_transactions: Option<u64>,
}

#[derive(cynic::Scalar, Debug, Clone)]
pub struct BigInt(pub String);
```

The complete example is shown below:

```rust, ignore
use eyre::Result;
use cynic::QueryBuilder;

use iota_graphql_client::{
    query_types::{schema, BigInt},
    GraphQLClient,
};
use iota_types::Address;

// The data returned by the custom query.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "SCHEMA_NAME_HERE", graphql_type = "Epoch")]
pub struct EpochData {
    pub epoch_id: u64,
    pub reference_gas_price: Option<BigInt>,
    pub total_gas_fees: Option<BigInt>,
    pub total_checkpoints: Option<u64>,
    pub total_transactions: Option<u64>,
}

// The variables to pass to the custom query.
// If an epoch id is passed, then the query will return the data for that epoch.
// Otherwise, the query will return the data for the last known epoch.
#[derive(cynic::QueryVariables, Debug)]
pub struct CustomVariables {
    pub id: Option<u64>,
}

// The custom query. Note that the variables need to be explicitly declared.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "SCHEMA_NAME_HERE", graphql_type = "Query", variables = "CustomVariables")]
pub struct CustomQuery {
    #[arguments(id: $id)]
    pub epoch: Option<EpochData>,
}

// Custom query with no variables.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "SCHEMA_NAME_HERE", graphql_type = "Query")]
pub struct ChainIdQuery {
    chain_identifier: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut client = GraphQLClient::new_devnet();

    // Query the data for the last known epoch. Note that id variable is None, so last epoch data
    // will be returned.
    let operation = CustomQuery::build(CustomVariables { id: None });
    let response = client
        .run_query::<CustomQuery, CustomVariables>(&operation)
        .await;
    println!("{:?}", response);

    // Query the data for epoch 1.
    let epoch_id = 1;
    let operation = CustomQuery::build(CustomVariables { id: Some(epoch_id) });
    let response = client
        .run_query::<CustomQuery, CustomVariables>(&operation)
        .await;
    println!("{:?}", response);

    // When the query has no variables, just pass () as the type argument
    let operation = ChainIdQuery::build(());
    let response = client.run_query::<ChainIdQuery, ()>(&operation).await?;
    if let Some(chain_id) = response.data {
        println!("Chain ID: {}", chain_id.chain_identifier);
    }

    Ok(())
}
```
