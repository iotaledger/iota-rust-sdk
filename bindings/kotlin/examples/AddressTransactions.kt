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
        val client = GraphQlClient.newLocalnet()
        val address =
            Address.fromHex("0xa7c2cf9d8f8d95ff69d7a598c49c77acc36253f496f064a533ad306879b40bfa")

        val outgoing = client.transactions(TransactionsFilter().withSentAddress(address))
        val incoming = client.transactions(TransactionsFilter().withRecvAddress(address))

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
