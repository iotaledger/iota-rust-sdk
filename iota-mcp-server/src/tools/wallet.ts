/**
 * Wallet tools for the IOTA MCP server.
 *
 * These tools communicate with the IOTA Agent Wallet server — a local HTTP
 * service that manages keys, signs transactions, and enforces human-in-the-loop
 * approval before any on-chain mutation.
 *
 * The wallet server address defaults to http://localhost:3847 and can be
 * overridden with the IOTA_WALLET_SERVER environment variable.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCommand, DEFAULT_WALLET_SERVER } from "../utils/index.js";

function walletUrl(): string {
  return process.env.IOTA_WALLET_SERVER || DEFAULT_WALLET_SERVER;
}

export function registerWalletTools(server: McpServer): void {
  // ── iota_wallet_address ─────────────────────────────────────────────
  server.tool(
    "iota_wallet_address",
    "Get the current IOTA Agent Wallet address",
    {},
    async () => {
      const result = await runCommand(
        `curl -s ${walletUrl()}/address`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_wallet_balance ─────────────────────────────────────────────
  server.tool(
    "iota_wallet_balance",
    "Get the IOTA balance of the current Agent Wallet",
    {},
    async () => {
      const result = await runCommand(
        `curl -s ${walletUrl()}/balance`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_wallet_accounts ────────────────────────────────────────────
  server.tool(
    "iota_wallet_accounts",
    "List all derived accounts in the IOTA Agent Wallet",
    {},
    async () => {
      const result = await runCommand(
        `curl -s ${walletUrl()}/accounts`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_wallet_pending ─────────────────────────────────────────────
  server.tool(
    "iota_wallet_pending",
    "View pending transaction signing requests awaiting human approval",
    {},
    async () => {
      const result = await runCommand(
        `curl -s ${walletUrl()}/pending`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_wallet_approve ─────────────────────────────────────────────
  server.tool(
    "iota_wallet_approve",
    "Approve a pending transaction by its request ID",
    {
      requestId: z
        .string()
        .describe("The request ID of the pending transaction to approve"),
    },
    async ({ requestId }) => {
      const result = await runCommand(
        `curl -s -X POST ${walletUrl()}/approve/${requestId}`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_wallet_reject ──────────────────────────────────────────────
  server.tool(
    "iota_wallet_reject",
    "Reject a pending transaction by its request ID",
    {
      requestId: z
        .string()
        .describe("The request ID of the pending transaction to reject"),
    },
    async ({ requestId }) => {
      const result = await runCommand(
        `curl -s -X POST ${walletUrl()}/reject/${requestId}`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_wallet_switch_network ──────────────────────────────────────
  server.tool(
    "iota_wallet_switch_network",
    "Switch the wallet network (mainnet, testnet, devnet, localnet)",
    {
      network: z
        .enum(["mainnet", "testnet", "devnet", "localnet"])
        .describe("Target network to switch to"),
    },
    async ({ network }) => {
      const body = JSON.stringify({ network });
      const result = await runCommand(
        `curl -s -X POST ${walletUrl()}/network ` +
          `-H "Content-Type: application/json" ` +
          `-d '${body}'`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_wallet_sign_execute ────────────────────────────────────────
  server.tool(
    "iota_wallet_sign_execute",
    "Sign and execute an unsigned transaction (base64-encoded transaction bytes). " +
      "The wallet enforces human-in-the-loop approval before broadcasting.",
    {
      txBytes: z
        .string()
        .describe("Base64-encoded unsigned transaction bytes"),
    },
    async ({ txBytes }) => {
      const body = JSON.stringify({ txBytes });
      const result = await runCommand(
        `curl -s -X POST ${walletUrl()}/sign-and-execute ` +
          `-H "Content-Type: application/json" ` +
          `-d '${body}'`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );
}
