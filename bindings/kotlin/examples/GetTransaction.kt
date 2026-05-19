// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.TransactionsFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()
        val latest =
            client.transactions(TransactionsFilter()).data.firstOrNull()
                ?: throw Exception("no transactions available on the network")
        val digest = latest.transaction.digest()
        println("Querying transaction: ${digest.toBase58()}")

        val signedTransaction = client.transaction(digest)
        println("Signed Transaction: ${signedTransaction?.toString()}\n")

        val transactionEffects = client.transactionEffects(digest)
        println("Transaction Effects: ${transactionEffects?.toString()}\n")

        val transactionDataEffects = client.transactionDataEffects(digest)
        println("Transaction Data Effects: ${transactionDataEffects?.toString()}\n")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
