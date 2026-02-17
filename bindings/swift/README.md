# IOTA SDK - Swift Bindings

Swift bindings for the IOTA SDK, enabling Swift developers to interact with the IOTA network.

## Installation

To use the IOTA SDK in your Swift project, add it as a dependency in your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/iotaledger/iota-sdk-swift.git", from: "0.0.1-alpha.1"),
]
```

The package includes pre-built native libraries for:

- macOS (x86_64 and ARM64)
- iOS (ARM64 and simulator)

## Quick Start

Here is a simple example that queries the chain ID from the IOTA network:

```swift
import IotaSDK

@main
struct ChainIdExample {
    static func main() async throws {
        let client = GraphQlClient.newDevnet()

        let chainId = try await client.chainId()
        print("Chain ID:", chainId)
    }
}
```

## Usage

The SDK provides GraphQL client functionality to interact with IOTA:

```swift
// Connect to devnet
let client = GraphQlClient.newDevnet()

// Connect to testnet
let client = GraphQlClient.newTestnet()

// Connect to mainnet
let client = GraphQlClient.newMainnet()

// Connect to a custom endpoint
let client = GraphQlClient.new(url: "https://your-endpoint.com")
```

## Examples

More examples are available in the [examples directory](https://github.com/iotaledger/iota-rust-sdk/tree/develop/bindings/swift/examples), including:

- Getting chain information
- Querying coin balances
- Working with transactions
- Managing addresses and keys
- And many more

## Building from Source

If you want to build the Swift bindings from the Rust source:

### Prerequisites

- GNU Make
- Swift 5.9+
- Rust toolchain

Verify by running `make --version`, `swift --version`, and `rustup --version`.

### Generate Swift bindings

```bash
make swift
```

### Run Swift examples

```sh
make swift-example chain_id
```
