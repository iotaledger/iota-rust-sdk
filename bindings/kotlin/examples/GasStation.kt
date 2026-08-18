// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()
        var gasStationUrl = "http://0.0.0.0:9527"
        var gasStationAuthToken = "test"
        var keypair = Ed25519PrivateKey.random()
        var sender = keypair.publicKey().deriveAddress()
        var signer = TransactionSigner.fromEd25519(keypair)

        val builder = TransactionBuilder(sender).withClient(client)

        builder.moveCall(
            Address.std(),
            Identifier("u64"),
            Identifier("sqrt"),
            listOf(PtbArgument.u64(64uL)),
        )

        builder.gasStationSponsor(
            gasStationUrl,
            headers = mapOf("Authorization" to listOf("Bearer $gasStationAuthToken")),
        )

        val res = builder.execute(signer)

        println("$res")

        println("Sponsored transaction was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
