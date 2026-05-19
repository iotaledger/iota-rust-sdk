// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

// A pre-encoded programmable transaction calling `0x1::u64::max(1, 2)` with
// empty gas-payment objects. Because the bytes do not reference any on-chain
// object refs, they stay valid across networks — the dry-run endpoint fills in
// gas coins on demand.
const val TX_BYTES_BASE64: String =
    "AAACAAgBAAAAAAAAAAAIAgAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA3U2NANtYXgAAgEAAAEBACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUiACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUi6AMAAAAAAAAAAAAAAAAAAAA="

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val transaction = Transaction.fromBase64(TX_BYTES_BASE64)

        val res = client.dryRunTx(transaction, false)

        if (res.error != null) {
            throw Exception("Dry run failed: ${res.error}")
        }

        println("Dry run was successful!")
        println("Dry run result: $res")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
