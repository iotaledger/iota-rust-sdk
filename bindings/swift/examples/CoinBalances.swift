// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct CoinBalancesExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let address = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: address, client: client)

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
