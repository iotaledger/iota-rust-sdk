// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val sender =
            Address.fromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

        FaucetClient.newLocalnet().requestAndWaitForFinalized(sender, client)

        val coinId =
            client.coins(sender).data.firstOrNull()?.id() ?: throw Exception("sender has no coins")

        val builder = TransactionBuilder(sender).withClient(client)

        builder
            .splitCoins(
                PtbArgument.objectId(coinId),
                listOf(PtbArgument.u64(1000uL), PtbArgument.u64(2000uL), PtbArgument.u64(3000uL)),
                listOf("coin1", "coin2", "coin3"),
            )
            .transferObjects(
                sender,
                listOf(
                    PtbArgument.assigned("coin1"),
                    PtbArgument.assigned("coin2"),
                    PtbArgument.assigned("coin3"),
                ),
            )

        val res = builder.dryRun(false)

        if (res.error != null) {
            throw Exception("Failed to split coins: ${res.error}")
        }

        println("Split coins dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
