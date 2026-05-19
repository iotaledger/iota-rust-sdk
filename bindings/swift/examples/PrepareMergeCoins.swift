// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareMergeCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let sender = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: sender, client: client)

    let coins = try await client.coins(owner: sender)
    guard coins.data.count >= 2 else {
      throw NSError(
        domain: "PrepareMergeCoins", code: 1,
        userInfo: [
          NSLocalizedDescriptionKey: "sender has only one coin, need two to merge"
        ])
    }
    let coin0 = PtbArgument.objectId(id: coins.data[0].id())
    let coin1 = PtbArgument.objectId(id: coins.data[1].id())

    let builder = TransactionBuilder(sender: sender).withClient(client: client)

    _ = builder.mergeCoins(primaryCoin: coin0, consumedCoins: [coin1])

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTx(tx: txn, skipChecks: false)
    if res.error != nil {
      throw NSError(
        domain: "PrepareMergeCoins", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to merge coins: \(res.error!)"])
    }

    print("Merge coins dry run was successful!")
  }
}
