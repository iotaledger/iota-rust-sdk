// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        // Get current epoch
        val currentEpoch = client.epoch(null)
        if (currentEpoch == null) {
            println("Current epoch is null")
            return@runBlocking
        }

        println("Current epoch: ${currentEpoch.epochId}")
        println("Current epoch start time: ${currentEpoch.startTimestamp}")

        if (currentEpoch.epochId == 0uL) {
            println("No previous epoch (current is epoch 0)")
            return@runBlocking
        }

        // Get previous epoch
        val previousEpochId = currentEpoch.epochId - 1uL
        val previousEpoch = client.epoch(previousEpochId)
        if (previousEpoch == null) {
            println("Previous epoch is null")
            return@runBlocking
        }

        println("Previous epoch: ${previousEpoch.epochId}")
        val rewards = previousEpoch.totalStakeRewards
        if (rewards != null) {
            println("Previous epoch stake rewards: $rewards")
        } else {
            println("Previous epoch stake rewards: <none>")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
