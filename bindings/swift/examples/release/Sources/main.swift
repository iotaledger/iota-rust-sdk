// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct Example {
  static func main() async throws {
    // Create a GraphQL client connected to devnet
    let client = GraphQlClient.newTestnet()

    // Query the chain ID
    let chainId = try await client.chainId()
    print("Chain ID:", chainId)
  }
}
