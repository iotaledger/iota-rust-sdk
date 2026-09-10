// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GrpcClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GrpcClient.newTestnet()

        // Pick a small range of recent checkpoints to stream.
        val latest = client.getCheckpointLatest()
        val start = latest.sequenceNumber - 4u

        val stream = client.streamCheckpoints(start, latest.sequenceNumber)

        while (true) {
            val checkpoint = stream.next() ?: break
            val summary = checkpoint.summary!!
            println(
                "Checkpoint ${checkpoint.sequenceNumber}: epoch ${summary.epoch()}, " +
                    "${summary.networkTotalTransactions()} total transactions, " +
                    "timestamp ${summary.timestampMs()}"
            )
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
