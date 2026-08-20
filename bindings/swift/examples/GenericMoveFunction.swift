// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct GenericMoveFunctionExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let sender = try Address.fromHex(
      hex: "0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e")

    let builder = client.transactionBuilder(sender: sender)

    let addr1 = try Address.fromHex(
      hex: "0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")
    let addr2 = try Address.fromHex(
      hex: "0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")

    _ = try builder.moveCall(
      package: Address.framework(),
      module: Identifier(identifier: "vec_map"),
      function: Identifier(identifier: "from_keys_values"),
      arguments: [
        PtbArgument.addressVec(addresses: [addr1, addr2]),
        PtbArgument.u64Vec(values: [10_000_000, 20_000_000]),
      ],
      typeArgs: [TypeTag.newAddress(), TypeTag.newU64()]
    )

    let res = try await builder.dryRun()

    if res.error != nil {
      throw NSError(
        domain: "GenericMoveFunction", code: 1,
        userInfo: [
          NSLocalizedDescriptionKey: "Failed to call generic Move function: \(res.error!)"
        ])
    }

    print("Successfully called generic Move function!")
  }
}
