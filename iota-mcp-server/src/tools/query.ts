/**
 * On-chain query tools for the IOTA MCP server.
 *
 * These tools let AI agents fetch object data, inspect balances, look up
 * transactions, and view decompiled contract source directly from the
 * IOTA blockchain.
 *
 * GraphQL queries use the same endpoints as the iota-sdk-graphql-client
 * Rust crate so results are consistent across language bindings.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  runCommand,
  graphqlQuery,
  formatGraphQLResult,
  IOTA_NETWORKS,
  type NetworkName,
} from "../utils/index.js";

// ─── GraphQL Queries ──────────────────────────────────────────────────

const OBJECT_QUERY = `
  query GetObject($objectId: IOTAAddress!) {
    object(address: $objectId) {
      address
      version
      digest
      storageRebate
      owner {
        ... on AddressOwner { owner { address } }
        ... on Shared { initialSharedVersion }
        ... on Immutable { __typename }
      }
      asMoveObject {
        contents {
          type { repr }
          json
        }
      }
      asMovePackage {
        address
      }
      previousTransactionBlock {
        digest
      }
    }
  }
`;

const BALANCE_QUERY = `
  query GetBalance($address: IOTAAddress!) {
    address(address: $address) {
      balance {
        totalBalance
        coinObjectCount
      }
      balances {
        nodes {
          coinType { repr }
          totalBalance
          coinObjectCount
        }
      }
    }
  }
`;

const TX_QUERY = `
  query GetTransaction($digest: String!) {
    transactionBlock(digest: $digest) {
      digest
      sender { address }
      gasInput {
        gasSponsor { address }
        gasPrice
        gasBudget
      }
      effects {
        status
        timestamp
        gasEffects {
          gasSummary {
            computationCost
            storageCost
            storageRebate
          }
        }
      }
    }
  }
`;

const COINS_QUERY = `
  query GetCoins($owner: IOTAAddress!, $coinType: String) {
    address(address: $owner) {
      coins(type: $coinType) {
        nodes {
          address
          balance
          coinType { repr }
        }
      }
    }
  }
`;

const OWNED_OBJECTS_QUERY = `
  query GetOwnedObjects($owner: IOTAAddress!, $first: Int) {
    address(address: $owner) {
      objects(first: $first) {
        nodes {
          address
          version
          digest
          asMoveObject {
            contents {
              type { repr }
              json
            }
          }
        }
      }
    }
  }
`;

export function registerQueryTools(server: McpServer): void {
  const networkSchema = z
    .enum(["mainnet", "testnet", "devnet", "localnet"])
    .default("mainnet")
    .describe("IOTA network to query (default: mainnet)");

  // ── iota_object ─────────────────────────────────────────────────────
  server.tool(
    "iota_object",
    "Fetch detailed on-chain information about an IOTA object by its ID, " +
      "including type, owner, contents, and version history.",
    {
      objectId: z
        .string()
        .describe("The object ID (hex address) to query"),
      network: networkSchema,
    },
    async ({ objectId, network }) => {
      const response = await graphqlQuery(
        OBJECT_QUERY,
        { objectId },
        network as NetworkName,
      );
      return {
        content: [{ type: "text", text: formatGraphQLResult(response) }],
      };
    },
  );

  // ── iota_balance ────────────────────────────────────────────────────
  server.tool(
    "iota_balance",
    "Check the IOTA balance and all coin balances for a given address.",
    {
      address: z
        .string()
        .describe("The IOTA address to check"),
      network: networkSchema,
    },
    async ({ address, network }) => {
      const response = await graphqlQuery(
        BALANCE_QUERY,
        { address },
        network as NetworkName,
      );
      return {
        content: [{ type: "text", text: formatGraphQLResult(response) }],
      };
    },
  );

  // ── iota_transaction ────────────────────────────────────────────────
  server.tool(
    "iota_transaction",
    "Fetch details of a transaction by its digest, including gas costs and effects.",
    {
      digest: z
        .string()
        .describe("The transaction digest to look up"),
      network: networkSchema,
    },
    async ({ digest, network }) => {
      const response = await graphqlQuery(
        TX_QUERY,
        { digest },
        network as NetworkName,
      );
      return {
        content: [{ type: "text", text: formatGraphQLResult(response) }],
      };
    },
  );

  // ── iota_coins ──────────────────────────────────────────────────────
  server.tool(
    "iota_coins",
    "List coin objects owned by an address, optionally filtered by coin type.",
    {
      owner: z
        .string()
        .describe("Owner address to list coins for"),
      coinType: z
        .string()
        .optional()
        .describe("Filter by coin type (e.g. '0x2::iota::IOTA')"),
      network: networkSchema,
    },
    async ({ owner, coinType, network }) => {
      const variables: Record<string, unknown> = { owner };
      if (coinType) variables.coinType = coinType;
      const response = await graphqlQuery(
        COINS_QUERY,
        variables,
        network as NetworkName,
      );
      return {
        content: [{ type: "text", text: formatGraphQLResult(response) }],
      };
    },
  );

  // ── iota_owned_objects ──────────────────────────────────────────────
  server.tool(
    "iota_owned_objects",
    "List objects owned by a given address (up to a specified limit).",
    {
      owner: z
        .string()
        .describe("Owner address"),
      limit: z
        .number()
        .default(10)
        .describe("Maximum number of objects to return (default: 10)"),
      network: networkSchema,
    },
    async ({ owner, limit, network }) => {
      const response = await graphqlQuery(
        OWNED_OBJECTS_QUERY,
        { owner, first: limit },
        network as NetworkName,
      );
      return {
        content: [{ type: "text", text: formatGraphQLResult(response) }],
      };
    },
  );

  // ── iota_decompile ──────────────────────────────────────────────────
  server.tool(
    "iota_decompile",
    "Get the IOTA Explorer URL for a published package so you can view " +
      "its decompiled/verified source code.",
    {
      packageId: z
        .string()
        .describe("The package ID (hex address) to view"),
      network: networkSchema,
    },
    async ({ packageId, network }) => {
      const explorerBase =
        IOTA_NETWORKS[network as NetworkName].explorer;
      const suffix =
        network === "mainnet" ? "" : `?network=${network}`;
      const url = `${explorerBase}/object/${packageId}${suffix}`;
      return {
        content: [
          {
            type: "text",
            text:
              `View package source on IOTA Explorer:\n${url}\n\n` +
              `You can also query the object directly with iota_object ` +
              `to inspect its on-chain representation.`,
          },
        ],
      };
    },
  );

  // ── iota_faucet ─────────────────────────────────────────────────────
  server.tool(
    "iota_faucet",
    "Request test IOTA tokens from the faucet (testnet/devnet/localnet only).",
    {
      address: z
        .string()
        .describe("The address to fund with test tokens"),
      network: z
        .enum(["testnet", "devnet", "localnet"])
        .default("testnet")
        .describe("Network faucet to use (default: testnet)"),
    },
    async ({ address, network }) => {
      const faucetUrl =
        IOTA_NETWORKS[network as "testnet" | "devnet" | "localnet"]
          .faucet;
      const body = JSON.stringify({
        FixedAmountRequest: { recipient: address },
      });
      const result = await runCommand(
        `curl -s -X POST ${faucetUrl}/gas ` +
          `-H "Content-Type: application/json" ` +
          `-d '${body}'`,
      );
      return { content: [{ type: "text", text: result }] };
    },
  );
}
