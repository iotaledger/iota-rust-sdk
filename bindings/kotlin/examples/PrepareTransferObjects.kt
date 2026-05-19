// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val fromAddress =
            Address.fromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
        val toAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        FaucetClient.newLocalnet().requestAndWaitForFinalized(fromAddress, client)

        val coins = client.coins(fromAddress).data
        if (coins.size < 3) {
            throw Exception("sender does not own at least 3 coin objects to transfer")
        }
        val objsToTransfer =
            listOf(
                PtbArgument.objectId(coins[0].id()),
                PtbArgument.objectId(coins[1].id()),
                PtbArgument.objectId(coins[2].id()),
            )

        val builder = TransactionBuilder(fromAddress).withClient(client)

        builder.transferObjects(toAddress, objsToTransfer)

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = client.dryRunTx(txn, false)

        if (res.error != null) {
            throw Exception("Failed to transfer objects: ${res.error}")
        }

        println("Transfer objects dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
