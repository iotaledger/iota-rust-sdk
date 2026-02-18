// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct CoinBalancesExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let address = try Address.fromHex(
      hex: "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f")

    let coins = try await client.coins(owner: address)
    for coin in coins.data {
      print(
        "Coin = \(coin.id().toHex()), Coin Type = \(coin.coinType().asStructTag()), Balance = \(coin.balance())"
      )
    }

    let balance = try await client.balance(address: address)
    print("Total Balance = \(String(describing: balance))")
  }
}
