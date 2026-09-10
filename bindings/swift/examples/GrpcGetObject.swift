// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GrpcGetObjectExample {
  static func main() async throws {
    let client = try GrpcClient.newTestnet()

    let objectId = try ObjectId.fromHex(
      hex: "0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")

    // `objects` is batched: it takes a list of ids and returns the objects in
    // the same order.
    let obj = try await client.objects(objectIds: [objectId])[0]

    print("Object ID:", obj.id().toHex())
    print("Version:", obj.version())
    print("Previous transaction:", obj.previousTransaction().toBase58())
    print("Owner:", obj.owner())
    print("Storage rebate:", obj.storageRebate())
    print("Type:", obj.objectType())
    print("BCS bytes:", hexEncode(input: obj.asStruct().contents))
  }
}
