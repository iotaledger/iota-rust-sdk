// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareSplitCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let sender = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    let coinId = try ObjectId.fromHex(
      hex: "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")

    let builder = client.transactionBuilder(sender: sender)

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
