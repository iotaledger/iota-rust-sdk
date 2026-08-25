// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareTransferObjectsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let fromAddress = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    let objsToTransfer = [
      try PtbArgument.objectIdFromHex(
        hex: "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db"
      ),
      try PtbArgument.objectIdFromHex(
        hex: "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc"
      ),
      try PtbArgument.objectIdFromHex(
        hex: "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2"
      ),
    ]

    let builder = client.transactionBuilder(sender: fromAddress)
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
