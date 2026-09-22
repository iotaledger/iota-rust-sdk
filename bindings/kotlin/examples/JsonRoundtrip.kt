// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example demonstrates how to convert a Transaction to and from JSON.
// A similar roundtrip can be done for other types as well.

import iota_sdk.*

fun main() {
    try {
        // A sample transaction in base64 format
        val txBytesBase64 =
            "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA="

        // Parse the transaction from base64
        val transaction = Transaction.fromBase64(txBytesBase64)

        // Convert the transaction to JSON
        val json = transaction.toJson()
        println("Transaction as JSON:\n$json")

        // Convert the JSON back to a transaction
        val transactionFromJson = Transaction.fromJson(json)
        println("Parsed transaction back from JSON: $transactionFromJson")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
