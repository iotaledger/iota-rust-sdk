// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

// A pre-encoded programmable transaction calling `0x1::u64::max(1, 2)` with
// empty gas-payment objects. Because the bytes do not reference any on-chain
// object refs, they stay valid across networks — the dry-run endpoint fills in
// gas coins on demand.
let txBytesBase64 =
  "AAACAAgBAAAAAAAAAAAIAgAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA3U2NANtYXgAAgEAAAEBACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUiACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUi6AMAAAAAAAAAAAAAAAAAAAA="

@main
struct DryRunBytesExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let transaction = try Transaction.fromBase64(base64: txBytesBase64)

    let res = try await client.dryRunTx(tx: transaction, skipChecks: false)
    if res.error != nil {
      throw NSError(
        domain: "DryRunBytes", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: \(res.error!)"])
    }

    print("Dry run was successful!")
    print("Dry run result: \(res)")
  }
}
