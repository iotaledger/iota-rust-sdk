// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct DevInspectExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let sender = Address.zero()
    let stdAddress = Address.std()

    let builder = TransactionBuilder(sender: sender).withClient(client: client)

    // Build a small chain of stdlib Move calls and extract the return value
    // from the final command via dry_run.

    // 1. max(100, 200) -> assign "max_value"
    _ = try builder.moveCall(
      package: stdAddress,
      module: Identifier(identifier: "u64"),
      function: Identifier(identifier: "max"),
      arguments: [PtbArgument.u64(value: 100), PtbArgument.u64(value: 200)],
      names: ["max_value"]
    )

    // 2. min(max_value, 150) -> assign "result"
    _ = try builder.moveCall(
      package: stdAddress,
      module: Identifier(identifier: "u64"),
      function: Identifier(identifier: "min"),
      arguments: [PtbArgument.assigned(name: "max_value"), PtbArgument.u64(value: 150)],
      names: ["result"]
    )

    let res = try await builder.dryRun(skipChecks: true)

    if res.error != nil {
      throw NSError(
        domain: "DevInspect", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to dry-run: \(res.error!)"])
    }

    // Extract the u64 return value from the last result.
    if let lastEffect = res.results.last,
      let returnValue = lastEffect.returnValues.first,
      returnValue.typeTag.isU64(),
      returnValue.bcs.count == 8
    {
      var value: UInt64 = 0
      for i in 0..<8 {
        value |= UInt64(returnValue.bcs[i]) << (8 * i)
      }
      print("min(max(100, 200), 150) = \(value)")
    } else {
      print("Failed to extract u64 from results")
    }
  }
}
