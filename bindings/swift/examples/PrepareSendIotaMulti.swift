// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct PrepareSendIotaMultiExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()
    let sender = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
    let coinId = try ObjectId.fromHex(
      hex: "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")

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

    let builder = client.transactionBuilder(sender: sender)

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

    let res = try await client.dryRunTx(tx: txn)

    if res.error != nil {
      throw NSError(
        domain: "PrepareSendIotaMulti", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to send IOTA: \(res.error!)"])
    }

    print("Send IOTA dry run was successful!")
  }
}
