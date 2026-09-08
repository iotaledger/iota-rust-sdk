// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct TxCommandResultsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let sender = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    let builder = client.transactionBuilder(sender: sender)

    let packageAddr = Address.std()
    let moduleName = try Identifier(identifier: "u64")
    let functionName = try Identifier(identifier: "max")

    _ = builder.moveCall(
      package: packageAddr,
      module: moduleName,
      function: functionName,
      arguments: [PtbArgument.u64(value: 0), PtbArgument.u64(value: 1000)],
      // Assign a name to the result of this command
      names: ["res0"]
    )

    _ = builder.moveCall(
      package: packageAddr,
      module: moduleName,
      function: functionName,
      arguments: [PtbArgument.u64(value: 1000), PtbArgument.u64(value: 2000)],
      // Assign a name to the result of this command
      names: ["res1"]
    )

    _ = builder.splitCoins(
      coin: PtbArgument.gas(),
      // Use the assigned results of previous commands as arguments
      amounts: [PtbArgument.assigned(name: "res0"), PtbArgument.assigned(name: "res1")],
      // For nested results, a tuple or vec can be used to assign them
      names: ["coin0", "coin1"]
    )

    // Use assigned results as arguments
    _ = builder.transferObjects(
      recipient: sender,
      objects: [PtbArgument.assigned(name: "coin0"), PtbArgument.assigned(name: "coin1")])

    let txn = try await builder.finish()

    print("Signing Digest:", txn.signingDigestHex())
    print("Txn Bytes:", txn.toBase64())

    let res = try await client.dryRunTransaction(transaction: txn, skipChecks: false)
    if res.error != nil {
      throw NSError(
        domain: "TxCommandResults", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to send tx: \(res.error!)"])
    }

    print("Tx dry run was successful!")
  }
}
