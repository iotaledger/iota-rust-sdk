# iota-sdk-grpc-client

The IOTA gRPC client provides access to the IOTA blockchain via gRPC. It exposes four service clients:

- **Ledger Service** — query blocks, transactions, and ledger state
- **Execution Service** — execute transactions and dry-run operations
- **State Service** — query on-chain objects and state
- **Move Package Service** — query and interact with Move packages

# Usage

## Connecting to a gRPC server

Instantiate a client with one of the predefined network constructors or `Client::new(url)` for a custom endpoint:

```rust
use iota_sdk_grpc_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to devnet
    let client = Client::new_devnet()?;

    // Access service clients
    let ledger = client.ledger_service_client();
    let execution = client.execution_service_client();
    let state = client.state_service_client();
    let move_package = client.move_package_service_client();

    Ok(())
}
```

## Network presets

The client provides `new_mainnet()`, `new_testnet()`, `new_devnet()`, `new_localnet()`, and `new(url)` for custom endpoints.

## Configuration

Customize headers and message size limits:

```rust
use iota_sdk_grpc_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new_devnet()?
        .with_headers(vec![("x-custom-header", "value")])
        .with_max_decoding_message_size(16 * 1024 * 1024); // 16MB

    Ok(())
}
```

## Service examples

Each service client exposes methods corresponding to the gRPC service definition. See the crate documentation for the full list of available methods.
