// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareMergeCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let sender = try Address.fromHex(
      hex: "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

    let coin0 = try PtbArgument.objectIdFromHex(
      hex: "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")
    let coin1 = try PtbArgument.objectIdFromHex(
      hex: "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")

    let builder = TransactionBuilder(sender: sender).withClient(client: client)

    _ = builder.mergeCoins(primaryCoin: coin0, consumedCoins: [coin1])

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await builder.dryRun()
    if res.error != nil {
      throw NSError(
        domain: "PrepareMergeCoins", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to merge coins: \(res.error!)"])
    }

    print("Merge coins dry run was successful!")
  }
}
