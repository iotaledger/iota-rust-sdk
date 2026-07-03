// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.TransactionDigest
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()
        val digest = TransactionDigest.fromBase58("3wN9oLKfvCjCd7uFW1D6fp1uSEsD3wJ2cU61YULNKzFh")

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
