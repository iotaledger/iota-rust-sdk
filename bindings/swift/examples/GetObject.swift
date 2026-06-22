// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct GetObjectExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let objectId = try ObjectId.fromHex(
      hex: "0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")

    guard let obj = try await client.object(objectId: objectId) else {
      throw NSError(
        domain: "GetObject", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "missing object"])
    }

    print("Object ID:", obj.id().toHex())
    print("Version:", obj.version())
    print("Previous transaction:", obj.previousTransaction().toBase58())
    print("Owner:", obj.owner())
    print("Storage rebate:", obj.storageRebate())
    print("Type:", obj.objectType())
    print("BCS bytes:", hexEncode(input: obj.asStruct().contents))
  }
}
