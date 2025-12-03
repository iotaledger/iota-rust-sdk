# IOTA SDK - Go Bindings

Go bindings for the IOTA SDK, enabling Go developers to interact with the IOTA network.

## Installation

To use the IOTA SDK in your Go project, add it as a dependency:

```bash
go get github.com/iotaledger/iota-sdk-go
```

The package includes pre-built native libraries for:

- macOS (x86_64 and ARM64)
- Linux (x86_64 and ARM64)
- Windows (x86_64 and ARM64)

## Quick Start

Here is a simple example that queries the chain ID from the IOTA network:

```go
package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-sdk-go/iota_sdk"
)

func main() {
	// Create a GraphQL client connected to devnet
	client := iota_sdk.GraphQlClientNewDevnet()

	// Query the chain ID
	chainID, err := client.ChainId()
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}
```

## Usage

The SDK provides GraphQL client functionality to interact with IOTA:

```go
// Connect to devnet
client := iota_sdk.GraphQlClientNewDevnet()

// Connect to testnet
client := iota_sdk.GraphQlClientNewTestnet()

// Connect to mainnet
client := iota_sdk.GraphQlClientNewMainnet()

// Connect to a custom endpoint
client := iota_sdk.GraphQlClientNew("https://your-endpoint.com")
```

## Examples

More examples are available in the [examples directory](https://github.com/iotaledger/iota-rust-sdk/tree/develop/bindings/go/examples), including:

- Getting chain information
- Querying coin balances
- Working with transactions
- Managing addresses and keys
- And many more

## Building from Source

If you want to build the Go bindings from the Rust source:

### Prerequisites

- GNU Make
- Go
- Rust toolchain
- uniffi-bindgen-go

Until https://github.com/NordSecurity/uniffi-bindgen-go/pull/77 is merged, it is recommended to install `uniffi-bindgen-go` via:

```bash
cargo install uniffi-bindgen-go --git https://github.com/filament-dm/uniffi-bindgen-go --rev ab7315502bd6b979207fdae854e87d531ee8764d
```

Verify by running `make --version`, `go version`, and `uniffi-bindgen-go --version`.

### Generate Go bindings

```bash
make go
```

### Run Go examples

```sh
make go-example chain_id
```
