# IOTA SDK - C# Bindings

C# bindings for the IOTA SDK, enabling C# developers to interact with the IOTA network.

> [!NOTE]
> Thanks to [Abhiraj Mengade](https://github.com/abhiraj-mengade) for adding these bindings.

## Installation

To use the IOTA SDK in your C# project, add it as a NuGet package:

```bash
dotnet add package IotaSdk
```

The package includes pre-built native libraries for:

- macOS (x86_64 and ARM64)
- Linux (x86_64 and ARM64)
- Windows (x86_64 and ARM64)

## Quick Start

Here is a simple example that queries the chain ID from the IOTA network:

```csharp
using System;
using System.Threading.Tasks;
using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        // Create a GraphQL client connected to devnet
        var client = GraphQlClient.NewDevnet();

        // Query the chain ID
        var chainId = await client.ChainId();
        Console.WriteLine($"Chain ID: {chainId}");
    }
}
```

## Usage

The SDK provides GraphQL client functionality to interact with IOTA:

```csharp
using IotaSdk;

// Connect to devnet
var client = GraphQlClient.NewDevnet();

// Connect to testnet
var client = GraphQlClient.NewTestnet();

// Connect to mainnet
var client = GraphQlClient.NewMainnet();

// Connect to a custom endpoint
var client = GraphQlClient.New("https://your-endpoint.com");

// Generate a mnemonic
var mnemonic = Iota.GenerateMnemonic(MnemonicLength.Words12);
```

## Examples

More examples are available in the [examples directory](https://github.com/iotaledger/iota-rust-sdk/tree/develop/bindings/csharp/examples), including:

- Getting chain information
- Querying coin balances
- Working with transactions
- Managing addresses and keys
- And many more

## Ledger

`Ledger` connects to the IOTA app on a Ledger hardware wallet, and a `LedgerSigner` signs transactions and personal messages with the key at one derivation path:

```csharp
var ledger = Ledger.NativeHid();
await ledger.OpenApp();
var signer = await ledger.Signer("m/44'/4218'/0'/0'/0'");

var builder = client.TransactionBuilder(signer.Address());
builder.SendIota(recipientAddress, PtbArgument.U64(1000));
var effects = await builder.Execute(TransactionSigner.FromLedger(signer), WaitForTransaction.Finalized);
```

The complete program is the [`LedgerSignSendIota`](https://github.com/iotaledger/iota-rust-sdk/tree/develop/bindings/csharp/examples/LedgerSignSendIota) example.

### USB

`Ledger.NativeHid` connects to the first Ledger device attached over USB, on Linux, macOS and Windows.

- Install the IOTA app on the device with Ledger Live and unlock the device. `OpenApp` opens the app.
- On Linux, install the udev rules from [LedgerHQ/udev-rules](https://github.com/LedgerHQ/udev-rules) so that a regular user can open the device.
- The native libraries of the released package are built without USB support, so `Ledger.NativeHid` fails with them. Those [built from source](#building-from-source) by `make csharp` have it; on Linux that build needs the `libudev` development package (`libudev-dev` on Debian and Ubuntu).

### Speculos

[Speculos](https://github.com/LedgerHQ/speculos) emulates a device running the IOTA app, for development without hardware. In a checkout of [iota-rust-sdk](https://github.com/iotaledger/iota-rust-sdk), `make speculos-start` runs it in Docker and `make speculos-stop` stops it; [Using Speculos](https://github.com/iotaledger/iota-rust-sdk/tree/develop/crates/iota-sdk-ledger#using-speculos) describes running it yourself. Connect with `Ledger.Speculos("127.0.0.1", 9999)` and approve requests in the emulator's web interface at <http://127.0.0.1:5001>.

With a local network running, `make ledger-example lang=csharp` starts the emulator, runs the example on it and approves the transaction.

### Host transport

To reach a device over a link the SDK does not provide, implement `LedgerTransport` and pass it to `Ledger.FromTransport`. Its `Exchange` method receives an APDU command and returns the device's answer, which ends with the two-byte status word.

### Clear and blind signing

The IOTA app shows what a transaction does when it can work that out from the transaction and its input objects. The transaction builder passes them to a `TransactionSigner.FromLedger` signer; `LedgerSigner.SignTransaction` sends none, and `SignTransactionWithObjects` takes them as an argument. A transaction the app cannot interpret is only signed when blind signing is enabled in the app's settings. Otherwise the device tells the user so, and `LedgerSigner` then fails with `LedgerException.BlindSigningDisabled`.

## Building from Source

If you want to build the C# bindings from the Rust source:

### Prerequisites

- GNU Make
- .NET 8.0 SDK or higher
- Rust toolchain
- uniffi-bindgen-cs

Install `uniffi-bindgen-cs` via:

```bash
make install-uniffi-bindgen-cs
```

Verify by running `make --version`, `dotnet --version`, and `uniffi-bindgen-cs --version`.

### Generate C# bindings

```bash
make csharp
```

### Run C# examples

```sh
make csharp-example ChainId
```

## Project Structure

```
bindings/csharp/
├── src/
│   └── IotaSdk/
│       ├── IotaSdk.csproj    # Project file
│       ├── IotaSdk.cs        # Generated bindings
│       └── libiota_sdk_ffi.* # Native library
├── examples/                 # Example projects
├── uniffi.toml              # Configuration
└── README.md                # This file
```

## Supported Frameworks

- .NET 8.0 and higher

## License

This project is licensed under the Apache License 2.0.
