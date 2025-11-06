// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val myAddress =
            Address.fromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

        val validators = client.activeValidators()
        if (validators.data.isEmpty()) {
            throw Exception("no validators found")
        }
        val validator = validators.data[0]

        println("Staking to validator ${validator.name ?: "with no name"}")

        val builder = TransactionBuilder(myAddress).withClient(client)

        builder.stake(PtbArgument.u64(1000000000uL), validator.address)

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to stake: ${res.error}")
        }

        println("Stake dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
