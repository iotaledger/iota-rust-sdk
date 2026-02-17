// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct DryRunBytesExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let txBytesBase64 =
      "AAACACAAAKSYS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA="
    let transaction = try Transaction.fromBase64(base64: txBytesBase64)

    let res = try await client.dryRunTx(tx: transaction)
    if res.error != nil {
      throw NSError(
        domain: "DryRunBytes", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: \(res.error!)"])
    }

    print("Dry run was successful!")
    print("Dry run result: \(res)")
  }
}
