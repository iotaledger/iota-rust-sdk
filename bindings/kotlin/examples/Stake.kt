// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Function
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.ObjectId
import iota_sdk.TransactionBuilder
import iota_sdk.UnresolvedInput
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

        val coin =
                client.`object`(
                        ObjectId.fromHex(
                                "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
                        )
                )
        if (coin == null) {
            throw Exception("missing coin")
        }

        val gasCoin =
                client.`object`(
                        ObjectId.fromHex(
                                "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
                        )
                )
        if (gasCoin == null) {
            throw Exception("missing gas coin")
        }

        val builder = TransactionBuilder()
        val inputs =
                listOf(
                        builder.input(UnresolvedInput.newShared(ObjectId.fromHex("0x5"), 1u, true)),
                        builder.input(UnresolvedInput.fromObject(coin).withOwnedKind()),
                        builder.input(UnresolvedInput.newPure(validator.address.toBytes())),
                )
        builder.moveCall(
                Function(
                        Address.fromHex("0x3"),
                        Identifier("iota_system"),
                        Identifier("request_add_stake"),
                ),
                inputs
        )
        builder.setSender(myAddress)
        builder.setGasBudget(50000000u)
        val refGasPrice = client.referenceGasPrice(null)
        if (refGasPrice == null) {
            throw Exception("missing ref gas price")
        }
        builder.setGasPrice(refGasPrice)
        builder.addGasObjects(listOf(UnresolvedInput.fromObject(gasCoin).withOwnedKind()))

        val txn = builder.finish()
        val res = client.dryRunTx(txn, false)

        if (res.error != null) {
            throw Exception("Failed to stake: ${res.error}")
        }

        println("Stake dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
