// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareTransferObjectsOfflineExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let privateKey = try Ed25519PrivateKey(bytes: Data(repeating: 9, count: 32))
    let fromAddress = privateKey.publicKey().deriveAddress()
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    // Request funds from faucet
    let faucet = FaucetClient.newLocalnet()
    _ = try await faucet.requestAndWaitForFinalized(address: fromAddress, client: client)

    let coins = try await client.objects(filter: ObjectFilter(owner: fromAddress)).data
    guard let gasCoin = coins.first else {
      throw NSError(
        domain: "PrepareTransferObjectsOffline", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "No coins found"])
    }
    let objsToTransfer = coins.dropFirst().map { PtbArgument.objectRef(id: $0.objectRef()) }
    let gasPrice = try await client.referenceGasPrice() ?? 100

    let builder = TransactionBuilder(sender: fromAddress)
    _ = builder.transferObjects(
      recipient: toAddress,
      objects: objsToTransfer
    )
    _ = builder.gas(objectRefs: [gasCoin.objectRef()]).gasPrice(price: gasPrice).gasBudget(
      budget: 500_000_000)

    let txn = try builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTransaction(transaction: txn)
    if res.error != nil {
      throw NSError(
        domain: "PrepareTransferObjectsOffline", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to transfer objects: \(res.error!)"])
    }

    print("Transfer objects dry run was successful!")
  }
}
