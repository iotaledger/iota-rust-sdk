// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareSplitCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let sender = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: sender, client: client)

    let coins = try await client.coins(owner: sender)
    guard let coin = coins.data.first else {
      throw NSError(
        domain: "PrepareSplitCoins", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "sender has no coins"])
    }
    let coinId = coin.id()

    let builder = TransactionBuilder(sender: sender).withClient(client: client)

    _ = builder.splitCoins(
      coin: PtbArgument.objectId(id: coinId),
      amounts: [
        PtbArgument.u64(value: 1000),
        PtbArgument.u64(value: 2000),
        PtbArgument.u64(value: 3000),
      ],
      names: ["coin1", "coin2", "coin3"]
    ).transferObjects(
      recipient: sender,
      objects: [
        PtbArgument.assigned(name: "coin1"),
        PtbArgument.assigned(name: "coin2"),
        PtbArgument.assigned(name: "coin3"),
      ]
    )

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await builder.dryRun(skipChecks: false)
    if res.error != nil {
      throw NSError(
        domain: "PrepareSplitCoins", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to split coins: \(res.error!)"])
    }

    print("Split coins dry run was successful!")
  }
}
