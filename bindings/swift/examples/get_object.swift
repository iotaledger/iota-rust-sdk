// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct GetObjectExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let objectId = try ObjectId.fromHex(
      hex: "0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e")

    guard let obj = try await client.object(objectId: objectId) else {
      throw NSError(
        domain: "GetObject", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "missing object"])
    }

    print("Object ID:", obj.objectId().toHex())
    print("Version:", obj.version())
    print("Previous transaction:", obj.previousTransaction().toBase58())
    print("Owner:", obj.owner())
    print("Storage rebate:", obj.storageRebate())
    print("Type:", obj.objectType())
    print("BCS bytes:", hexEncode(input: obj.asStruct().contents))
  }
}
