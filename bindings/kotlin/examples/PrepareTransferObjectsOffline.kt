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

        // Prefetch object refs and gas price online so the rest of the example
        // can be assembled offline.
        FaucetClient.newLocalnet().requestAndWaitForFinalized(fromAddress, client)
        val owned =
            client.objects(
                ObjectFilter(owner = fromAddress, typeTag = "0x2::coin::Coin<0x2::iota::IOTA>")
            )
        if (owned.data.size < 4) {
            throw Exception("sender does not own at least 4 coins (1 for gas + 3 to transfer)")
        }
        val gasCoin = owned.data[0]
        val objsToTransfer =
            listOf(
                PtbArgument.objectRef(owned.data[1].objectRef()),
                PtbArgument.objectRef(owned.data[2].objectRef()),
                PtbArgument.objectRef(owned.data[3].objectRef()),
            )
        var gasPrice = client.referenceGasPrice()

        // From here on, no further network calls are made; the transaction is
        // assembled entirely from the prefetched object refs.
        val builder = TransactionBuilder(fromAddress)

        builder.transferObjects(toAddress, objsToTransfer)
        builder.gas(listOf(gasCoin.objectRef())).gasPrice(gasPrice ?: 100uL).gasBudget(500000000uL)

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = client.dryRunTx(txn)

        if (res.error != null) {
            throw Exception("Failed to transfer objects: ${res.error}")
        }

        println("Transfer objects dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
