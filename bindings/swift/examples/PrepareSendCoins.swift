// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareSendCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let fromAddress = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    // This is a coin of type
    // 0xfce9c14e5f0c2b65787debb8145a33a4a2fc83152e8939000b862e174bc86bb8::cert::CERT
    let coinId = try PtbArgument.objectIdFromHex(
      hex: "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2")

    let builder = client.transactionBuilder(sender: fromAddress)
    _ = builder.sendCoins(
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
