// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.ObjectId
import iota_sdk.PtbArgument
import iota_sdk.TransactionBuilder
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val myAddress =
                Address.fromHex(
                        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
                )

        val validators = client.activeValidators()
        if (validators.data.isEmpty()) {
            throw Exception("no validators found")
        }
        val validator = validators.data[0]

        println("Staking to validator ${validator.name ?: "with no name"}")

        val coinId =
                ObjectId.fromHex(
                        "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
                )

        val builder = TransactionBuilder.init(myAddress, client)

        builder.moveCall(
                Address.fromHex("0x3"),
                Identifier("iota_system"),
                Identifier("request_add_stake"),
                listOf(
                        PtbArgument.sharedMut(ObjectId.fromHex("0x5")),
                        PtbArgument.objectId(coinId),
                        PtbArgument.address(validator.address)
                ),
        )

        val res = builder.dryRun(true)

        if (res.error != null) {
            throw Exception("Failed to stake: ${res.error}")
        }

        println("Stake dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
