# IOTA SDK - TypeScript Bindings

TypeScript bindings for the IOTA SDK, enabling TypeScript/JavaScript developers to interact with the IOTA network.

## Installation

To use the IOTA SDK in your TypeScript project, install it via npm:

```bash
npm install @iota/sdk
```

The package includes pre-built native libraries for:

- macOS (x86_64 and ARM64)
- Linux (x86_64 and ARM64)
- Windows (x86_64 and ARM64)

## Quick Start

Here is a simple example that queries the chain ID from the IOTA network:

```typescript
import { GraphQlClient } from "@iota/sdk";

async function main() {
  // Create a GraphQL client connected to devnet
  const client = GraphQlClient.newDevnet();

  // Query the chain ID
  const chainId = await client.chainId();
  console.log("Chain ID:", chainId);
}

main();
```

## Usage

The SDK provides GraphQL client functionality to interact with IOTA:

```typescript
// Connect to devnet
const client = GraphQlClient.newDevnet();

// Connect to testnet
const client = GraphQlClient.newTestnet();

// Connect to mainnet
const client = GraphQlClient.newMainnet();

// Connect to a custom endpoint
const client = GraphQlClient.new("https://your-endpoint.com");

// Generate a mnemonic
import { generateMnemonic, MnemonicLength } from "@iota/sdk";
const mnemonic = generateMnemonic(MnemonicLength.WORDS12);
```

## Examples

More examples are available in the [examples directory](https://github.com/iotaledger/iota-rust-sdk/tree/develop/bindings/typescript/examples), including:

- Getting chain information
- Querying coin balances
- Working with transactions
- Managing addresses and keys
- And many more

## Building from Source

If you want to build the TypeScript bindings from the Rust source:

### Prerequisites

- GNU Make
- Node.js 22+
- Rust toolchain
- uniffi-bindgen-node

Install `uniffi-bindgen-node` via:

```bash
cargo install uniffi-bindgen-node --git https://github.com/nicklimmm/uniffi-bindgen-node --branch main
```

Verify by running `make --version`, `node --version`, and `uniffi-bindgen-node --version`.

### Generate TypeScript bindings

```bash
make typescript
```

### Run TypeScript examples

```sh
make typescript-example chain_id
```

## Project Structure

```
bindings/typescript/
├── package.json            # Package configuration
├── tsconfig.json           # TypeScript configuration
├── lib/
│   ├── iota_sdk.js         # Generated bindings
│   ├── iota_sdk.d.ts       # TypeScript type declarations
│   └── libiota_sdk_ffi.*   # Native library
├── examples/               # Example scripts
├── uniffi.toml             # UniFFI configuration
└── README.md               # This file
```

## License

This project is licensed under the Apache License 2.0.
