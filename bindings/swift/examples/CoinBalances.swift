// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct CoinBalancesExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let address = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    let coins = try await client.coins(owner: address)
    for coin in coins.data {
      print(
        "Coin = \(coin.id().toHex()), Coin Type = \(coin.coinType().asStructTag()), Balance = \(coin.balance())"
      )
    }

    let balance = try await client.balance(address: address) ?? 0
    print("Total Balance = \(balance)")
  }
}
