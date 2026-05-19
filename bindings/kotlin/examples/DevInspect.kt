// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlin.collections.emptyList
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val sender = Address.zero()
        val stdAddress = Address.std()

        val builder = TransactionBuilder(sender).withClient(client)

        // Build a small chain of stdlib Move calls and extract the return value
        // from the final command via dry_run.
        builder.moveCall(
            stdAddress,
            Identifier("u64"),
            Identifier("max"),
            listOf(PtbArgument.u64(100uL), PtbArgument.u64(200uL)),
            emptyList(),
            listOf("max_value"),
        )

        builder.moveCall(
            stdAddress,
            Identifier("u64"),
            Identifier("min"),
            listOf(PtbArgument.assigned("max_value"), PtbArgument.u64(150uL)),
            emptyList(),
            listOf("result"),
        )

        val res = builder.dryRun(true)

        if (res.error != null) {
            throw Exception("Failed to dry-run: ${res.error}")
        }

        // Extract the resolved u64 from the last result
        if (res.results.isNotEmpty()) {
            val lastEffect = res.results.last()
            if (lastEffect.returnValues.isNotEmpty()) {
                val returnValue = lastEffect.returnValues.first()
                if (returnValue.typeTag.isU64() && returnValue.bcs.size == 8) {
                    var value = 0uL
                    for (i in 7 downTo 0) {
                        value = (value shl 8) or (returnValue.bcs[i].toUByte().toULong())
                    }
                    println("min(max(100, 200), 150) = $value")
                } else {
                    println("Failed to extract u64 from results")
                }
            } else {
                println("Failed to extract u64 from results")
            }
        } else {
            println("Failed to extract u64 from results")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
