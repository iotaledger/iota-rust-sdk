// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct ChainIdExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let chainId = try await client.chainId()
    print("Chain ID:", chainId)
  }
}
