// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareSplitCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let sender = try Address.fromHex(
      hex: "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

    let coinId = try ObjectId.fromHex(
      hex: "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")

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

    let res = try await builder.dryRun()
    if res.error != nil {
      throw NSError(
        domain: "PrepareSplitCoins", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to split coins: \(res.error!)"])
    }

    print("Split coins dry run was successful!")
  }
}
