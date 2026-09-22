// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareMergeCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let sender = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    let coin0 = try PtbArgument.objectIdFromHex(
      hex: "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")
    let coin1 = try PtbArgument.objectIdFromHex(
      hex: "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")

    let builder = client.transactionBuilder(sender: sender)

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
