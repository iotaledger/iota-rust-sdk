// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.ObjectId
import iota_sdk.TransactionsFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        // The IOTA system state object (0x5) is a well-known shared object
        // that is present on every network including localnet.
        val sharedObjId = ObjectId.systemState()
        val transactions = client.transactions(TransactionsFilter(inputObject = sharedObjId))

        for (transaction in transactions.data) {
            println("Digest: ${transaction.transaction.digest().toBase58()}")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
