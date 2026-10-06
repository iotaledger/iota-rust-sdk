# iota-sdk-grpc-client

The IOTA gRPC client provides access to the IOTA blockchain via gRPC. It wraps the low-level proto
types and provides ergonomic APIs using SDK types from `iota_types`, on top of four service clients:

- **Ledger Service** — query blocks, transactions, and ledger state
- **Execution Service** — execute transactions and dry-run operations
- **State Service** — query on-chain objects and state
- **Move Package Service** — query and interact with Move packages

## Usage

### Connecting to a gRPC server

Instantiate a client with one of the predefined network constructors or `GrpcClient::new(url)` for a custom endpoint:

```rust,no_run
use iota_sdk_grpc_client::GrpcClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to devnet
    let client = GrpcClient::new_devnet()?;

    // Access service clients
    let ledger = client.ledger_service_client();
    let execution = client.execution_service_client();
    let state = client.state_service_client();
    let move_package = client.move_package_service_client();

    Ok(())
}
```

### Network presets

The client provides `new_mainnet()`, `new_testnet()`, `new_devnet()`, `new_localnet()`, and `new(url)` for custom endpoints.

### TLS

`https://` endpoints, including the mainnet, testnet and devnet presets, are verified with `rustls`.
The defaults reach them with no setup.

| Feature            | Default | Effect                                                                                                                    |
| ------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------- |
| `tls-ring`         | on      | `ring` as the `rustls` crypto provider                                                                                    |
| `tls-aws-lc`       | off     | `aws-lc-rs` instead; builds a C library, so it needs a C toolchain. `tls-ring` wins if both are on.                       |
| neither provider   | —       | HTTP-only: `GrpcClient::new` rejects an `https://` address. The build to use against a localnet.                          |
| `tls-native-roots` | on      | trust the platform certificate store. `GrpcClient::new` fails for an `https://` address if the store has no certificates. |
| `tls-webpki-roots` | off     | trust the bundled Mozilla roots, merged into the platform store when `tls-native-roots` is also on                        |
| neither roots      | —       | HTTP-only, as with no provider                                                                                            |

A crypto provider the application has installed as the process default
(`rustls::crypto::CryptoProvider::install_default`) is used instead of the one the features select.

### Configuration

Customize headers and message size limits:

```rust,no_run
use iota_sdk_grpc_client::{GrpcClient, HeadersInterceptor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut headers = HeadersInterceptor::new();
    headers.headers_mut().insert("x-custom-header", "value".parse()?);

    let client = GrpcClient::new_devnet()?
        .with_headers(headers)
        .with_max_decoding_message_size(16 * 1024 * 1024); // 16MB

    Ok(())
}
```

### Reading data

The batched reads return one result per request, so an item the node cannot serve fails only its
own slot:

```rust,no_run
use iota_sdk_grpc_client::GrpcClient;
use iota_types::{ObjectId, TransactionDigest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = GrpcClient::new_localnet()?;

    // Get a transaction with the default field mask.
    let digest: TransactionDigest = todo!();
    let txs = client.transactions([digest]).await?;
    for tx in txs.body() {
        match tx {
            Ok(tx) => println!("Transaction digest: {:?}", tx.transaction()?.digest()?),
            Err(e) => eprintln!("could not read transaction: {e}"),
        }
    }

    // Get an object with the default field mask.
    let object_id: ObjectId = "0x2".parse()?;
    let objects = client.objects([object_id]).await?;
    for object in objects.body() {
        match object {
            Ok(object) => println!("Object version: {:?}", object.object_reference()?.version()),
            Err(e) => eprintln!("could not read object: {e}"),
        }
    }
    Ok(())
}
```

### Service examples

Each service client exposes methods corresponding to the gRPC service definition. See the crate documentation for the full list of available methods.
