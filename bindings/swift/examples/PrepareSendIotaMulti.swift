// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareSendIotaMultiExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()
    let sender = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: sender, client: client)

    let coins = try await client.coins(owner: sender)
    guard let coin = coins.data.first else {
      throw NSError(
        domain: "PrepareSendIotaMulti", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "sender has no coins"])
    }
    let coinId = coin.id()

    let recipients: [(String, UInt64)] = [
      (
        "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11",
        1_000_000_000
      ),
      (
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522",
        2_000_000_000
      ),
    ]

    let amounts = recipients.map { PtbArgument.u64(value: $0.1) }
    let labels = (0..<recipients.count).map { "coin\($0)" }

    let builder = TransactionBuilder(sender: sender).withClient(client: client)

    _ = builder.splitCoins(
      coin: PtbArgument.objectId(id: coinId), amounts: amounts, names: labels)
    for (i, r) in recipients.enumerated() {
      _ = builder.transferObjects(
        recipient: try Address.fromHex(hex: r.0),
        objects: [PtbArgument.assigned(name: labels[i])])
    }

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTx(tx: txn, skipChecks: false)

    if res.error != nil {
      throw NSError(
        domain: "PrepareSendIotaMulti", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to send IOTA: \(res.error!)"])
    }

    print("Send IOTA dry run was successful!")
  }
}
