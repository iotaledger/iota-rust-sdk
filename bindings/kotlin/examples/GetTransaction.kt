// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Digest
import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
  try {
    val client = GraphQlClient.newDevnet()
    val digest = Digest.fromBase58("Agug2GETToZj4Ncw3RJn2KgDUEpVQKG1WaTZVcLcqYnf")

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
