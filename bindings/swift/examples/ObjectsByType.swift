// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct ObjectsByTypeExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let coins = try await client.objects(
      filter: ObjectFilter(typeTag: "0x2::coin::Coin<0x2::iota::IOTA>"))

    if coins.data.isEmpty {
      print("No IOTA coin objects found")
    } else {
      print("IOTA coin object IDs:")
      for coin in coins.data {
        print(coin.id().toHex())
      }
    }
  }
}
