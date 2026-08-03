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

    // Filtering objects by type alone scans every object on the network, which
    // the GraphQL server rejects with a timeout. Pick a recent staker and filter
    // by owner as well, so only that address' objects are looked at.
    let stakers = try await client.transactions(
      filter: TransactionsFilter(function: "0x3::iota_system::request_add_stake"),
      paginationFilter: PaginationFilter(direction: .backward, limit: 1))

    guard let staker = stakers.data.last?.transaction.sender() else {
      print("No staking transactions on testnet right now.")
      return
    }

    print("Latest staker: \(staker.toHex())\n")

    let page = try await client.objects(
      filter: ObjectFilter(typeTag: "0x3::staking_pool::StakedIota", owner: staker))

    if page.data.isEmpty {
      print("No StakedIota objects owned by \(staker.toHex()) right now.")
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
