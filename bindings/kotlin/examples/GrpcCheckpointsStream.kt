// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GrpcClient
import kotlinx.coroutines.runBlocking

const val HOW_MANY = 5uL

fun main() = runBlocking {
    try {
        val client = GrpcClient.newLocalnet()

        // Pick a starting point a few checkpoints behind head so the example
        // returns promptly instead of waiting on new blocks.
        val head = client.checkpointLatest().sequenceNumber
        val start = if (head >= HOW_MANY - 1uL) head - (HOW_MANY - 1uL) else 0uL
        val end = head

        // Only ask for the summary, which keeps the message small. Pass null (or
        // compose more fields) to pull more data per checkpoint.
        val stream = client.checkpointsStream(start, end, readMask = listOf("checkpoint.summary"))

        println("Streaming checkpoints $start..=$end")
        while (true) {
            val checkpoint = stream.next() ?: break
            val summary =
                checkpoint.summary
                    ?: error("Checkpoint ${checkpoint.sequenceNumber} has no summary")
            println(
                "  cp ${checkpoint.sequenceNumber.toString().padStart(6)}  " +
                    "epoch ${summary.epoch().toString().padStart(3)}  " +
                    "txs ${summary.networkTotalTransactions().toString().padStart(4)}  " +
                    "ts ${summary.timestampMs()}"
            )
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
