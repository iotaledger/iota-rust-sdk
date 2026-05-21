// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Fetch all transactions for an address (outgoing and incoming).
//
// The GraphQL service does not have a single filter that returns transactions
// in both directions for an address. To get the full history, run two queries
// and merge the results.

import iota_sdk.Address
import iota_sdk.GraphQlClient
import iota_sdk.TransactionsFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()
        val address =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

        val outgoing = client.transactions(TransactionsFilter(signAddress = address))
        val incoming = client.transactions(TransactionsFilter(recvAddress = address))

        println("Transactions for ${address.toHex()}")

        println("\nOutgoing (sent by address): ${outgoing.data.size}")
        for (tx in outgoing.data) {
            println("  - ${tx.transaction.digest().toBase58()}")
        }

        println("\nIncoming (received by address): ${incoming.data.size}")
        for (tx in incoming.data) {
            println("  - ${tx.transaction.digest().toBase58()}")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
