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
