# IOTA SDK - Swift Bindings

Swift bindings for the IOTA SDK, enabling Swift developers to interact with the IOTA network.

> [!NOTE]
> Thanks to [Cyber](https://github.com/shaibuafeez) for adding these bindings.

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
        let client = try GraphQlClient.newDevnet()

        let chainId = try await client.chainId()
        print("Chain ID:", chainId)
    }
}
```

## Usage

The SDK provides GraphQL client functionality to interact with IOTA:

```swift
// Connect to devnet
let client = try GraphQlClient.newDevnet()

// Connect to testnet
let client = try GraphQlClient.newTestnet()

// Connect to mainnet
let client = try GraphQlClient.newMainnet()

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

## Ledger

`Ledger` connects to the IOTA app on a Ledger hardware wallet, and a `LedgerSigner` signs transactions and personal messages with the key at one derivation path:

```swift
let ledger = try Ledger.nativeHid()
try await ledger.openApp()
let signer = try await ledger.signer(path: "m/44'/4218'/0'/0'/0'")

let builder = client.transactionBuilder(sender: signer.address())
_ = builder.sendIota(recipient: recipientAddress, amount: PtbArgument.u64(value: 1000))
let effects = try await builder.execute(
  signer: TransactionSigner.fromLedger(signer: signer), waitFor: WaitForTransaction.finalized)
```

The complete program is the [`LedgerSignSendIota`](https://github.com/iotaledger/iota-rust-sdk/blob/develop/bindings/swift/examples/LedgerSignSendIota.swift) example.

### USB

`Ledger.nativeHid` connects to the first Ledger device attached over USB, on macOS and Linux.

- Install the IOTA app on the device with Ledger Live and unlock the device. `openApp` opens the app.
- On Linux, install the udev rules from [LedgerHQ/udev-rules](https://github.com/LedgerHQ/udev-rules) so that a regular user can open the device.
- The native libraries of the released package are built without USB support, so `Ledger.nativeHid` fails with them. The library [built from source](#building-from-source) by `make swift` has it; on Linux that build needs the `libudev` development package (`libudev-dev` on Debian and Ubuntu).

### Speculos

[Speculos](https://github.com/LedgerHQ/speculos) emulates a device running the IOTA app, for development without hardware. In a checkout of [iota-rust-sdk](https://github.com/iotaledger/iota-rust-sdk), `make speculos-start` runs it in Docker and `make speculos-stop` stops it; [Using Speculos](https://github.com/iotaledger/iota-rust-sdk/tree/develop/crates/iota-sdk-ledger#using-speculos) describes running it yourself. Connect with `Ledger.speculos(host: "127.0.0.1", port: 9999)` and approve requests in the emulator's web interface at <http://127.0.0.1:5001>.

With a local network running, `make ledger-example lang=swift` starts the emulator, runs the example on it and approves the transaction.

### Host transport

The iOS libraries cannot open USB devices. To reach a device there, or over any other link the SDK does not provide, implement `LedgerTransport` on top of that link, such as Bluetooth through Ledger's mobile SDKs, and pass it to `Ledger.fromTransport`:

```swift
final class BluetoothTransport: LedgerTransport {
  func exchange(apdu: Data) async throws -> Data {
    // Send the APDU command to the device and return its answer, which
    // ends with the two-byte status word
  }
}

let ledger = Ledger.fromTransport(transport: BluetoothTransport())
```

### Clear and blind signing

The IOTA app shows what a transaction does when it can work that out from the transaction and its input objects. The transaction builder passes them to a `TransactionSigner.fromLedger` signer; `LedgerSigner.signTransaction` sends none, and `signTransactionWithObjects` takes them as an argument. A transaction the app cannot interpret is only signed when blind signing is enabled in the app's settings. Otherwise the device tells the user so, and `LedgerSigner` then fails with `LedgerError.BlindSigningDisabled`.

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
