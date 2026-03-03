// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        // Get current epoch
        val currentEpoch = client.epoch(null)
        if (currentEpoch == null) {
            println("Current epoch is null")
            return@runBlocking
        }

        println("Current epoch: ${currentEpoch.epochId}")
        println("Current epoch start time: ${currentEpoch.startTimestamp}")

        // Get previous epoch
        val previousEpochId = currentEpoch.epochId - 1u
        val previousEpoch = client.epoch(previousEpochId)
        if (previousEpoch == null) {
            println("Previous epoch is null")
            return@runBlocking
        }

        println("Previous epoch: ${previousEpoch.epochId}")
        previousEpoch.totalStakeRewards?.let { rewards ->
            println("Previous epoch stake rewards: $rewards")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
