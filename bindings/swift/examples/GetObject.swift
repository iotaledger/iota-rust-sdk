// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct GetObjectExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let address = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: address, client: client)

    let coins = try await client.coins(owner: address)
    guard let firstCoin = coins.data.first else {
      throw NSError(
        domain: "GetObject", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "address has no coins after faucet request"])
    }
    let objectId = firstCoin.id()

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
