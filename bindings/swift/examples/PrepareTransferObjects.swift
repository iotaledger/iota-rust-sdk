// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareTransferObjectsExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let fromAddress = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: fromAddress, client: client)

    let coins = try await client.coins(owner: fromAddress)
    guard coins.data.count >= 3 else {
      throw NSError(
        domain: "PrepareTransferObjects", code: 1,
        userInfo: [
          NSLocalizedDescriptionKey:
            "sender does not own at least 3 coin objects to transfer"
        ])
    }
    let objsToTransfer = coins.data[0..<3].map { PtbArgument.objectId(id: $0.id()) }

    let builder = TransactionBuilder(sender: fromAddress).withClient(client: client)
    _ = builder.transferObjects(
      recipient: toAddress,
      objects: Array(objsToTransfer)
    )

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTx(tx: txn, skipChecks: false)
    if res.error != nil {
      throw NSError(
        domain: "PrepareTransferObjects", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to transfer objects: \(res.error!)"])
    }

    print("Transfer objects dry run was successful!")
  }
}
