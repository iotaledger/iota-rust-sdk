# iota-agent-mcp

MCP (Model Context Protocol) server that exposes IOTA blockchain tools to AI coding agents — Claude Code, Cursor, VS Code Copilot, ChatGPT, and any other MCP-compatible client.

## Features

- **17 tools** spanning wallet management, Move development, and on-chain queries
- **Direct GraphQL queries** against IOTA mainnet/testnet/devnet/localnet
- **Human-in-the-loop signing** via the IOTA Agent Wallet
- **Full Move workflow** — build, test with coverage, publish
- **Network-aware** — switch between mainnet, testnet, devnet, and localnet
- **Faucet integration** — request test tokens on testnet/devnet

## Quick Start

### Install globally

```bash
npm install -g iota-agent-mcp
```

### Or run directly with npx

```bash
npx iota-agent-mcp
```

### Configure your MCP client

Add to your Claude Code config (`.mcp.json`) or equivalent:

```json
{
  "mcpServers": {
    "iota": {
      "command": "iota-agent-mcp"
    }
  }
}
```

For Cursor, add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "iota": {
      "command": "npx",
      "args": ["-y", "iota-agent-mcp"]
    }
  }
}
```

## Prerequisites

- **Node.js** >= 18.0.0
- **IOTA CLI** — for Move development tools (`iota_cli`, `iota_move_build`, etc.)
  - Install: https://docs.iota.org/developer/getting-started/install-iota
- **IOTA Agent Wallet** (optional) — for transaction signing tools
  - The wallet server runs locally and provides human-in-the-loop approval

## Tools Reference

### Wallet Tools (8)

| Tool | Description |
|------|-------------|
| `iota_wallet_address` | Get current wallet address |
| `iota_wallet_balance` | Check IOTA balance |
| `iota_wallet_accounts` | List all derived accounts |
| `iota_wallet_pending` | View pending signing requests |
| `iota_wallet_approve` | Approve a pending transaction |
| `iota_wallet_reject` | Reject a pending transaction |
| `iota_wallet_switch_network` | Switch network (mainnet/testnet/devnet/localnet) |
| `iota_wallet_sign_execute` | Sign and execute unsigned transaction bytes |

### CLI & Move Tools (4)

| Tool | Description |
|------|-------------|
| `iota_cli` | Run any IOTA CLI command |
| `iota_move_build` | Build a Move package |
| `iota_move_test_coverage` | Run Move tests with coverage analysis |
| `iota_move_publish_unsigned` | Generate unsigned publish transaction |

### On-chain Query Tools (5)

| Tool | Description |
|------|-------------|
| `iota_object` | Fetch object data via GraphQL |
| `iota_balance` | Check address balance via GraphQL |
| `iota_transaction` | Fetch transaction details by digest |
| `iota_coins` | List coin objects for an address |
| `iota_owned_objects` | List objects owned by an address |
| `iota_decompile` | Get explorer URL for package source |
| `iota_faucet` | Request test tokens from faucet |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IOTA_WALLET_SERVER` | `http://localhost:3847` | Agent wallet HTTP server address |
| `IOTA_NETWORK` | `mainnet` | Default network for queries |

## Network Endpoints

The server uses the same GraphQL endpoints as the `iota-sdk-graphql-client` Rust crate:

| Network | GraphQL | Explorer |
|---------|---------|----------|
| mainnet | `https://graphql.mainnet.iota.cafe` | `https://explorer.iota.org` |
| testnet | `https://graphql.testnet.iota.cafe` | `https://explorer.iota.org` |
| devnet | `https://graphql.devnet.iota.cafe` | `https://explorer.iota.org` |
| localnet | `http://localhost:9125/graphql` | `http://localhost:9001` |

## Architecture

```
iota-mcp-server/
├── src/
│   ├── index.ts              # Entry point — server setup and transport
│   ├── tools/
│   │   ├── wallet.ts         # Wallet management tools (8)
│   │   ├── cli.ts            # CLI and Move development tools (4)
│   │   ├── query.ts          # On-chain query tools (5)
│   │   └── index.ts          # Tool registration barrel
│   └── utils/
│       ├── command.ts         # Shell command execution
│       ├── constants.ts       # Network endpoints and defaults
│       ├── graphql.ts         # Lightweight GraphQL client
│       └── index.ts           # Utils barrel
├── package.json
├── tsconfig.json
└── README.md
```

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build

# Run the built server
npm start
```

## How It Works

1. **MCP Transport**: The server communicates over stdio using the Model Context Protocol, making it compatible with any MCP client.

2. **GraphQL Queries**: On-chain data is fetched via IOTA's GraphQL API (same endpoints as the Rust SDK), providing typed, efficient queries for objects, balances, transactions, and coins.

3. **CLI Wrapping**: Move development tools delegate to the `iota` CLI binary, giving agents full access to build, test, and publish workflows.

4. **Wallet Integration**: Transaction signing uses a local Agent Wallet server that enforces human-in-the-loop approval — the AI agent can prepare and submit transactions, but a human must approve before anything is broadcast on-chain.

## Security Model

- **No private keys in the MCP server** — all signing happens through the separate Agent Wallet
- **Human-in-the-loop** — transactions require explicit human approval before execution
- **Read-only by default** — most tools only query on-chain data
- **Local-only wallet** — the wallet server runs on localhost, never exposed to the internet

## License

Apache-2.0 — see [LICENSE](../LICENSE)
