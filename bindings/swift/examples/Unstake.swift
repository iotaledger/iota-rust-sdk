// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct UnstakeExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let owner = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    let stakedIotas = try await client.objects(
      filter: ObjectFilter(
        typeTag: String(describing: StructTag.newStakedIota()), owner: owner))
    if stakedIotas.data.isEmpty {
      throw NSError(
        domain: "Unstake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "no staked iotas found"])
    }
    let stakedIota = stakedIotas.data[0]

    let builder = client.transactionBuilder(sender: stakedIota.owner().asAddress())

    _ = builder.unstake(stakedIota: PtbArgument.objectId(id: stakedIota.id()))

    let res = try await builder.dryRun()
    if res.error != nil {
      throw NSError(
        domain: "Unstake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to unstake: \(res.error!)"])
    }

    print("Unstake dry run was successful!")
  }
}
