// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Tail transactions as they are executed, over a GraphQL subscription.
//
// Unlike the paginated queries, a subscription never ends on its own: it is
// pulled one update at a time and stopped with `cancel`. Localnet may be idle,
// so the example asks the faucet for coins to generate a transaction, and
// cancels after a deadline so it cannot hang.

import iota_sdk.Address
import iota_sdk.FaucetClient
import iota_sdk.GraphQlClient
import iota_sdk.TransactionUpdate
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

const val DEADLINE_MILLIS = 60_000L

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()
        val subscription = client.transactionsSubscription()

        val activity = launch {
            // Give the subscription a moment to connect before generating
            // activity, otherwise the transaction lands before anyone is
            // listening.
            delay(2_000)
            val address =
                Address.fromHex(
                    "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
                )
            FaucetClient.newLocalnet().requestAndWait(address)
        }
        // Cancelling unblocks a pending `next`, which is what keeps the example
        // from waiting forever on a network that produces nothing.
        val watchdog = launch {
            delay(DEADLINE_MILLIS)
            subscription.cancel()
        }

        println("Waiting for a transaction...")
        while (true) {
            val update = subscription.next()
            if (update == null) {
                println("No transaction observed within ${DEADLINE_MILLIS}ms")
                kotlin.system.exitProcess(1)
            }

            when (update) {
                is TransactionUpdate.Transaction -> {
                    val transaction = update.transaction.transaction
                    println("Digest: ${transaction.digest().toBase58()}")
                    println("Sender: ${transaction.sender().toHex()}")
                    break
                }
                // Delivery recovers on its own; items in the gap may be missed.
                is TransactionUpdate.Interrupted -> println("Interrupted: ${update.message}")
            }
        }

        watchdog.cancel()
        activity.cancel()
        subscription.cancel()
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
