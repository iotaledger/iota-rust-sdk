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

        val coins = client.coins(sender).data
        val coinIds = coins.iterator()
        val coin0 =
            PtbArgument.objectId(
                if (coinIds.hasNext()) coinIds.next().id()
                else throw Exception("sender has no coins to merge")
            )
        val coin1 =
            PtbArgument.objectId(
                if (coinIds.hasNext()) coinIds.next().id()
                else throw Exception("sender has only one coin, need two to merge")
            )

        val builder = TransactionBuilder(sender).withClient(client)

        builder.mergeCoins(coin0, listOf(coin1))

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = client.dryRunTx(txn, false)

        if (res.error != null) {
            throw Exception("Failed to merge coins: ${res.error}")
        }

        println("Merge coins dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
