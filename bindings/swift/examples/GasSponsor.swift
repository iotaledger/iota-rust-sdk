// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct GasSponsorExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let sender = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    let sponsor = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    let builder = client.transactionBuilder(sender: sender)

    _ = try builder.moveCall(
      package: Address.std(),
      module: Identifier(identifier: "u8"),
      function: Identifier(identifier: "max"),
      arguments: [PtbArgument.u8(value: 0), PtbArgument.u8(value: 1)]
    )

    _ = builder.sponsor(sponsor: sponsor)

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTx(tx: txn)
    if res.error != nil {
      throw NSError(
        domain: "GasSponsor", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to send gas sponsor tx: \(res.error!)"]
      )
    }

    print("Gas sponsor tx dry run was successful!")
  }
}
