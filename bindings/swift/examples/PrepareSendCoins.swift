// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareSendCoinsExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let fromAddress = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    let toAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: fromAddress, client: client)

    let coins = try await client.coins(owner: fromAddress)
    guard let coin = coins.data.first else {
      throw NSError(
        domain: "PrepareSendCoins", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "sender has no coins"])
    }

    let builder = TransactionBuilder(sender: fromAddress).withClient(client: client)
    _ = builder.sendCoins(
      coins: [PtbArgument.objectId(id: coin.id())],
      recipient: toAddress,
      amount: PtbArgument.u64(value: 50_000_000_000)
    )

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTx(tx: txn, skipChecks: false)
    if res.error != nil {
      throw NSError(
        domain: "PrepareSendCoins", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to send coins: \(res.error!)"])
    }

    print("Send coins dry run was successful!")
  }
}
