// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Decode `StakedIota` objects into typed Kotlin values.
//
// The GraphQL client returns each object's contents as raw BCS bytes. A single
// `StakedIota.tryFromObject(obj)` call gives typed, named-field access to
// id / poolId / stakeActivationEpoch / principal.

import iota_sdk.Direction
import iota_sdk.GraphQlClient
import iota_sdk.ObjectFilter
import iota_sdk.PaginationFilter
import iota_sdk.StakedIota
import iota_sdk.TransactionsFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        // Filtering objects by type alone scans every object on the network, which the
        // GraphQL server rejects with a timeout. Pick a recent staker and filter by owner
        // as well, so only that address' objects are looked at.
        val stakers =
            client.transactions(
                TransactionsFilter(function = "0x3::iota_system::request_add_stake"),
                PaginationFilter(direction = Direction.BACKWARD, limit = 1),
            )

        val staker = stakers.data.lastOrNull()?.transaction?.sender()
        if (staker == null) {
            println("No staking transactions on testnet right now.")
            return@runBlocking
        }

        println("Latest staker: ${staker.toHex()}\n")

        val page =
            client.objects(ObjectFilter(typeTag = "0x3::staking_pool::StakedIota", owner = staker))

        if (page.data.isEmpty()) {
            println("No StakedIota objects owned by ${staker.toHex()} right now.")
            return@runBlocking
        }

        println("Decoded ${page.data.size} StakedIota object(s):\n")
        var totalPrincipal = 0UL
        for (obj in page.data) {
            val staked = StakedIota.tryFromObject(obj)
            totalPrincipal += staked.principal()
            println("- id:               ${staked.id().toHex()}")
            println("  pool_id:          ${staked.poolId().toHex()}")
            println("  stake_activation_epoch: ${staked.stakeActivationEpoch()}")
            println("  principal (nanos): ${staked.principal()}")
            println()
        }

        println("Total principal across page: $totalPrincipal nanos")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
