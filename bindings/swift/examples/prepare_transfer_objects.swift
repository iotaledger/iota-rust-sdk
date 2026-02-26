// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareTransferObjectsExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let fromAddress = try Address.fromHex(
      hex: "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    let objsToTransfer = [
      try PtbArgument.objectIdFromHex(
        hex: "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
      ),
      try PtbArgument.objectIdFromHex(
        hex: "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
      ),
      try PtbArgument.objectIdFromHex(
        hex: "0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9"
      ),
    ]

    let builder = TransactionBuilder(sender: fromAddress).withClient(client: client)
    _ = builder.transferObjects(
      recipient: toAddress,
      objects: objsToTransfer
    )

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTx(tx: txn)
    if res.error != nil {
      throw NSError(
        domain: "PrepareTransferObjects", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to transfer objects: \(res.error!)"])
    }

    print("Transfer objects dry run was successful!")
  }
}
