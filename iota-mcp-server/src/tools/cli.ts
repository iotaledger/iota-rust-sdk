/**
 * CLI and Move development tools for the IOTA MCP server.
 *
 * These tools wrap the `iota` CLI binary, enabling AI agents to build, test,
 * and publish Move smart contracts without leaving the conversation.
 *
 * Prerequisites:
 *   - `iota` CLI installed and available on PATH
 *     (see https://docs.iota.org/developer/getting-started/install-iota)
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCommand, DEFAULT_WALLET_SERVER } from "../utils/index.js";

function walletUrl(): string {
  return process.env.IOTA_WALLET_SERVER || DEFAULT_WALLET_SERVER;
}

export function registerCliTools(server: McpServer): void {
  // ── iota_cli ────────────────────────────────────────────────────────
  server.tool(
    "iota_cli",
    "Run any IOTA CLI command (e.g. 'client gas', 'move build', 'client object <id>'). " +
      "The `iota` prefix is added automatically.",
    {
      args: z
        .string()
        .describe("Arguments to pass to the `iota` CLI"),
      cwd: z
        .string()
        .optional()
        .describe("Working directory for the command"),
    },
    async ({ args, cwd }) => {
      const result = await runCommand(`iota ${args}`, cwd);
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_move_build ─────────────────────────────────────────────────
  server.tool(
    "iota_move_build",
    "Build a Move package. Returns compiler output including any errors or warnings.",
    {
      packagePath: z
        .string()
        .describe("Absolute path to the Move package directory"),
    },
    async ({ packagePath }) => {
      const result = await runCommand("iota move build", packagePath);
      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_move_test_coverage ─────────────────────────────────────────
  server.tool(
    "iota_move_test_coverage",
    "Run Move tests with coverage tracing. Optionally summarize coverage for a specific module.",
    {
      packagePath: z
        .string()
        .describe("Absolute path to the Move package directory"),
      module: z
        .string()
        .optional()
        .describe("Specific module name to generate a coverage summary for"),
    },
    async ({ packagePath, module }) => {
      let result = await runCommand(
        "iota move test --coverage --trace",
        packagePath,
      );

      if (module) {
        result += "\n\n--- Coverage Summary ---\n";
        result += await runCommand(
          `iota move coverage summary --module ${module}`,
          packagePath,
        );
      }

      return { content: [{ type: "text", text: result }] };
    },
  );

  // ── iota_move_publish_unsigned ──────────────────────────────────────
  server.tool(
    "iota_move_publish_unsigned",
    "Generate unsigned transaction bytes for publishing a Move package. " +
      "Use with `iota_wallet_sign_execute` to sign and broadcast.",
    {
      packagePath: z
        .string()
        .describe("Absolute path to the Move package directory"),
      gasBudget: z
        .number()
        .default(100_000_000)
        .describe(
          "Gas budget in NANOS (default 100 000 000 = 0.1 IOTA)",
        ),
    },
    async ({ packagePath, gasBudget }) => {
      // Fetch the agent wallet address so we can set the sender
      const addrResult = await runCommand(
        `curl -s ${walletUrl()}/address`,
      );

      let address: string;
      try {
        address = JSON.parse(addrResult).address;
      } catch {
        return {
          content: [
            {
              type: "text",
              text: `Failed to get wallet address: ${addrResult}`,
            },
          ],
        };
      }

      const result = await runCommand(
        `iota client publish --serialize-unsigned-transaction ` +
          `--sender ${address} --gas-budget ${gasBudget}`,
        packagePath,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );
}
