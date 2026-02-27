/**
 * Lightweight GraphQL client for querying the IOTA blockchain.
 *
 * Uses the same endpoints exposed by the iota-sdk-graphql-client Rust crate
 * so that results are consistent across languages.
 */

import { IOTA_NETWORKS, type NetworkName } from "./constants.js";

export interface GraphQLResponse<T = unknown> {
  data?: T;
  errors?: Array<{ message: string; locations?: unknown; path?: unknown }>;
}

/**
 * Execute a GraphQL query against the IOTA network.
 */
export async function graphqlQuery<T = unknown>(
  query: string,
  variables: Record<string, unknown> = {},
  network: NetworkName = "mainnet",
): Promise<GraphQLResponse<T>> {
  const endpoint = IOTA_NETWORKS[network].graphql;

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "iota-agent-mcp/1.0.0",
    },
    body: JSON.stringify({ query, variables }),
  });

  if (!res.ok) {
    throw new Error(`GraphQL request failed: ${res.status} ${res.statusText}`);
  }

  return (await res.json()) as GraphQLResponse<T>;
}

/**
 * Format a GraphQL response for display. Returns the JSON data on success
 * or an error summary on failure.
 */
export function formatGraphQLResult<T>(response: GraphQLResponse<T>): string {
  if (response.errors && response.errors.length > 0) {
    return `GraphQL errors:\n${response.errors.map((e) => `  - ${e.message}`).join("\n")}`;
  }
  return JSON.stringify(response.data, null, 2);
}
