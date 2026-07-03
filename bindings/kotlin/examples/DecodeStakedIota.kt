// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Decode `StakedIota` objects into typed Kotlin values.
//
// The GraphQL client returns each object's contents as raw BCS bytes. A single
// `StakedIota.tryFromObject(obj)` call gives typed, named-field access to
// id / poolId / stakeActivationEpoch / principal.

import iota_sdk.GraphQlClient
import iota_sdk.ObjectFilter
import iota_sdk.StakedIota
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()
        val page = client.objects(ObjectFilter(typeTag = "0x3::staking_pool::StakedIota"))

        if (page.data.isEmpty()) {
            println("No StakedIota objects on testnet right now.")
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
