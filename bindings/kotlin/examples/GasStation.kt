// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Ed25519PrivateKey
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.PtbArgument
import iota_sdk.SimpleKeypair
import iota_sdk.TransactionBuilder
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()
        var gasStationUrl = "http://0.0.0.0:9527"
        var gasStationAuthToken = "test"
        var keypair = Ed25519PrivateKey.generate()
        var sender = keypair.publicKey().deriveAddress()
        var simpleKey = SimpleKeypair.fromEd25519(keypair)

        val builder = TransactionBuilder.init(sender, client)

        builder.moveCall(
                Address.stdLib(),
                Identifier("u64"),
                Identifier("sqrt"),
                listOf(
                        PtbArgument.u64(64uL),
                )
        )

        builder.gasStationSponsor(
                gasStationUrl,
                headers = mapOf("Authorization" to listOf("Bearer $gasStationAuthToken"))
        )

        val res = builder.execute(simpleKey, true)

        if (res != null) {
            println("$res")
        }

        println("Sponsored transaction was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
