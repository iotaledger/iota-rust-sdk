// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val sender =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
        val sponsor =
            Address.fromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

        FaucetClient.newLocalnet().requestAndWaitForFinalized(sponsor, client)

        val builder = TransactionBuilder(sender).withClient(client)

        val packageAddr = Address.std()
        val moduleName = Identifier("u8")
        val functionName = Identifier("max")

        builder.moveCall(
            packageAddr,
            moduleName,
            functionName,
            listOf(PtbArgument.u8(0u), PtbArgument.u8(1u)),
        )

        builder.sponsor(sponsor)

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = client.dryRunTx(txn, false)

        if (res.error != null) {
            throw Exception("Failed to send gas sponsor tx: ${res.error}")
        }

        println("Gas sponsor tx dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
