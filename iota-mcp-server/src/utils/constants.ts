/**
 * Network constants for IOTA blockchain.
 *
 * GraphQL endpoints are sourced from the iota-sdk-graphql-client crate:
 *   crates/iota-sdk-graphql-client/src/client.rs
 *
 * Faucet endpoints are sourced from:
 *   crates/iota-sdk-graphql-client/src/faucet.rs
 */

export const IOTA_NETWORKS = {
  mainnet: {
    graphql: "https://graphql.mainnet.iota.cafe",
    explorer: "https://explorer.iota.org",
  },
  testnet: {
    graphql: "https://graphql.testnet.iota.cafe",
    explorer: "https://explorer.iota.org",
    faucet: "https://faucet.testnet.iota.cafe",
  },
  devnet: {
    graphql: "https://graphql.devnet.iota.cafe",
    explorer: "https://explorer.iota.org",
    faucet: "https://faucet.devnet.iota.cafe",
  },
  localnet: {
    graphql: "http://localhost:9125/graphql",
    explorer: "http://localhost:9001",
    faucet: "http://localhost:9123",
  },
} as const;

export type NetworkName = keyof typeof IOTA_NETWORKS;

/**
 * Default wallet server address for the IOTA Agent Wallet.
 * Overridden by the IOTA_WALLET_SERVER environment variable.
 */
export const DEFAULT_WALLET_SERVER = "http://localhost:3847";
