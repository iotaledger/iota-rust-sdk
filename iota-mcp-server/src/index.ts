#!/usr/bin/env node
/**
 * IOTA MCP Server
 *
 * Model Context Protocol server that exposes IOTA blockchain tools to AI
 * coding agents (Claude Code, Cursor, VS Code Copilot, ChatGPT, etc.).
 *
 * Tools (17 total):
 *
 *   Wallet (8):
 *     iota_wallet_address      – Get current wallet address
 *     iota_wallet_balance      – Check IOTA balance
 *     iota_wallet_accounts     – List all derived accounts
 *     iota_wallet_pending      – View pending signing requests
 *     iota_wallet_approve      – Approve a pending transaction
 *     iota_wallet_reject       – Reject a pending transaction
 *     iota_wallet_switch_network – Switch network
 *     iota_wallet_sign_execute – Sign and execute a transaction
 *
 *   CLI & Move (4):
 *     iota_cli                 – Run any IOTA CLI command
 *     iota_move_build          – Build a Move package
 *     iota_move_test_coverage  – Run tests with coverage analysis
 *     iota_move_publish_unsigned – Generate unsigned publish transaction
 *
 *   On-chain Queries (5):
 *     iota_object              – Fetch object data via GraphQL
 *     iota_balance             – Check address balance via GraphQL
 *     iota_transaction         – Fetch transaction details
 *     iota_coins               – List coin objects for an address
 *     iota_owned_objects       – List objects owned by an address
 *     iota_decompile           – Get explorer URL for package source
 *     iota_faucet              – Request test tokens from faucet
 *
 * Environment variables:
 *   IOTA_WALLET_SERVER  – Agent wallet HTTP address (default: http://localhost:3847)
 *   IOTA_NETWORK        – Default network: mainnet | testnet | devnet | localnet
 *
 * Usage with Claude Code:
 *   Add to ~/.claude/plugins.json or .mcp.json:
 *   {
 *     "mcpServers": {
 *       "iota": { "command": "iota-agent-mcp" }
 *     }
 *   }
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  registerWalletTools,
  registerCliTools,
  registerQueryTools,
} from "./tools/index.js";

const server = new McpServer({
  name: "iota-mcp",
  version: "1.0.0",
});

// Register all tool groups
registerWalletTools(server);
registerCliTools(server);
registerQueryTools(server);

// Start the server
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("IOTA MCP Server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error starting IOTA MCP Server:", err);
  process.exit(1);
});
