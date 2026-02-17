// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareSendCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let fromAddress = try Address.fromHex(
      hex: "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    // This is a coin of type
    // 0x3358bea865960fea2a1c6844b6fc365f662463dd1821f619838eb2e606a53b6a::cert::CERT
    let coinId = try PtbArgument.objectIdFromHex(
      hex: "0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9")

    let builder = TransactionBuilder(sender: fromAddress).withClient(client: client)
    builder.sendCoins(
      coins: [coinId],
      recipient: toAddress,
      amount: PtbArgument.u64(value: 50_000_000_000)
    )

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await builder.dryRun()
    if res.error != nil {
      throw NSError(
        domain: "PrepareSendCoins", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to send coins: \(res.error!)"])
    }

    print("Send coins dry run was successful!")
  }
}
