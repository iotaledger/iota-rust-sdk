// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.ObjectId
import iota_sdk.TransactionsFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val sharedObjId =
                ObjectId.fromHex(
                        "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
                )
        val transactions = client.transactions(TransactionsFilter(inputObject = sharedObjId))

        for (transaction in transactions.data) {
            println("Digest: ${transaction.transaction.digest().toBase58()}")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
