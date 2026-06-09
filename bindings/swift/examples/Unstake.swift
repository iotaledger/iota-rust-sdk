// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct UnstakeExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let stakedIotas = try await client.objects(
      filter: ObjectFilter(typeTag: String(describing: StructTag.newStakedIota())))
    if stakedIotas.data.isEmpty {
      throw NSError(
        domain: "Unstake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "no staked iotas found"])
    }
    let stakedIota = stakedIotas.data[0]

    let builder = TransactionBuilder(sender: stakedIota.owner().asAddress()).withClient(
      client: client)

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
