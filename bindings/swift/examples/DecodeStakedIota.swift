// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Decode `StakedIota` objects into typed Swift values.
//
// The GraphQL client returns each object's contents as raw BCS bytes. A single
// `StakedIota.tryFromObject(object: obj)` call gives typed, named-field access
// to id / poolId / stakeActivationEpoch / principal.

import IotaSDK

@main
struct DecodeStakedIotaExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()
    let page = try await client.objects(
      filter: ObjectFilter(typeTag: "0x3::staking_pool::StakedIota"))

    if page.data.isEmpty {
      print("No StakedIota objects on testnet right now.")
      return
    }

    print("Decoded \(page.data.count) StakedIota object(s):\n")
    var totalPrincipal: UInt64 = 0
    for obj in page.data {
      let staked = try StakedIota.tryFromObject(object: obj)
      totalPrincipal += staked.principal()
      print("- id:               \(staked.id().toHex())")
      print("  pool_id:          \(staked.poolId().toHex())")
      print("  stake_activation_epoch: \(staked.stakeActivationEpoch())")
      print("  principal (nanos): \(staked.principal())\n")
    }

    print("Total principal across page: \(totalPrincipal) nanos")
  }
}
