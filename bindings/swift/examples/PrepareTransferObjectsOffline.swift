// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareTransferObjectsOfflineExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let fromAddress = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    // Prefetch object refs and gas price online so the rest of the example can
    // be assembled offline.
    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: fromAddress, client: client)
    let owned = try await client.objects(
      filter: ObjectFilter(
        typeTag: "0x2::coin::Coin<0x2::iota::IOTA>",
        owner: fromAddress
      ))
    guard owned.data.count >= 4 else {
      throw NSError(
        domain: "PrepareTransferObjectsOffline", code: 1,
        userInfo: [
          NSLocalizedDescriptionKey:
            "sender does not own at least 4 coins (1 for gas + 3 to transfer)"
        ])
    }
    let gasCoinRef = owned.data[0].objectRef()
    let objsToTransfer = owned.data[1..<4].map { PtbArgument.objectRef(id: $0.objectRef()) }
    let gasPrice = try await client.referenceGasPrice() ?? 100

    // From here on, no further network calls are made; the transaction is
    // assembled entirely from the prefetched object refs.
    let builder = TransactionBuilder(sender: fromAddress)
    _ = builder.transferObjects(
      recipient: toAddress,
      objects: Array(objsToTransfer)
    )
    _ = builder.gas(objectRefs: [gasCoinRef]).gasPrice(price: gasPrice).gasBudget(
      budget: 500_000_000)

    let txn = try builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTx(tx: txn, skipChecks: false)
    if res.error != nil {
      throw NSError(
        domain: "PrepareTransferObjectsOffline", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to transfer objects: \(res.error!)"])
    }

    print("Transfer objects dry run was successful!")
  }
}
