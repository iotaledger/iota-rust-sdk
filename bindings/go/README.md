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
	client, err := iota_sdk.GraphQlClientNewDevnet()
	if err != nil {
		log.Fatalf("Failed to create GraphQL client: %v", err)
	}

	// Query the chain ID
	chainID, err := client.ChainId()
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}
```

## Usage

The SDK provides GraphQL client functionality to interact with IOTA:

```go
// Connect to devnet
client, err := iota_sdk.GraphQlClientNewDevnet()

// Connect to testnet
client, err := iota_sdk.GraphQlClientNewTestnet()

// Connect to mainnet
client, err := iota_sdk.GraphQlClientNewMainnet()

// Connect to a custom endpoint
client, err := iota_sdk.GraphQlClientNew("https://your-endpoint.com")
```

## Examples

More examples are available in the [examples directory](https://github.com/iotaledger/iota-rust-sdk/tree/develop/bindings/go/examples), including:

- Getting chain information
- Querying coin balances
- Working with transactions
- Managing addresses and keys
- And many more

## Ledger

`Ledger` connects to the IOTA app on a Ledger hardware wallet, and a `LedgerSigner` signs transactions and personal messages with the key at one derivation path:

```go
ledger, err := iota_sdk.LedgerNativeHid()
if err != nil {
	log.Fatalf("Failed to connect to the Ledger device: %v", err)
}
if err := ledger.OpenApp(); err != nil {
	log.Fatalf("Failed to open the IOTA app: %v", err)
}
signer, err := ledger.Signer("m/44'/4218'/0'/0'/0'")
if err != nil {
	log.Fatalf("Failed to create the signer: %v", err)
}

builder := client.TransactionBuilder(signer.Address())
builder.SendIota(recipientAddress, iota_sdk.PtbArgumentU64(1000))
waitFor := iota_sdk.WaitForTransactionFinalized
effects, err := builder.Execute(iota_sdk.TransactionSignerFromLedger(signer), &waitFor)
```

The complete program is the [`ledger_sign_send_iota`](https://github.com/iotaledger/iota-rust-sdk/tree/develop/bindings/go/examples/ledger_sign_send_iota) example.

### USB

`LedgerNativeHid` connects to the first Ledger device attached over USB, on Linux, macOS and Windows.

- Install the IOTA app on the device with Ledger Live and unlock the device. `OpenApp` opens the app.
- On Linux, install the udev rules from [LedgerHQ/udev-rules](https://github.com/LedgerHQ/udev-rules) so that a regular user can open the device.
- The native libraries of the released package are built without USB support, so `LedgerNativeHid` fails with them. Those [built from source](#building-from-source) by `make go` have it; on Linux that build needs the `libudev` development package (`libudev-dev` on Debian and Ubuntu).

### Speculos

[Speculos](https://github.com/LedgerHQ/speculos) emulates a device running the IOTA app, for development without hardware. In a checkout of [iota-rust-sdk](https://github.com/iotaledger/iota-rust-sdk), `make speculos-start` runs it in Docker and `make speculos-stop` stops it; [Using Speculos](https://github.com/iotaledger/iota-rust-sdk/tree/develop/crates/iota-sdk-ledger#using-speculos) describes running it yourself. Connect with `LedgerSpeculos("127.0.0.1", 9999)` and approve requests in the emulator's web interface at <http://127.0.0.1:5001>.

With a local network running, `make ledger-example lang=go` starts the emulator, runs the example on it and approves the transaction.

### Host transport

To reach a device over a link the SDK does not provide, implement `LedgerTransport` and pass it to `LedgerFromTransport`. Its `Exchange` method receives an APDU command and returns the device's answer, which ends with the two-byte status word.

### Clear and blind signing

The IOTA app shows what a transaction does when it can work that out from the transaction and its input objects. The transaction builder passes them to a `TransactionSignerFromLedger` signer; `LedgerSigner.SignTransaction` sends none, and `SignTransactionWithObjects` takes them as an argument. A transaction the app cannot interpret is only signed when blind signing is enabled in the app's settings. Otherwise the device tells the user so, and `LedgerSigner` then fails with `ErrLedgerErrorBlindSigningDisabled`.

## Building from Source

If you want to build the Go bindings from the Rust source:

### Prerequisites

- GNU Make
- Go
- Rust toolchain
- uniffi-bindgen-go

Install `uniffi-bindgen-go` via:

```bash
make install-uniffi-bindgen-go
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
