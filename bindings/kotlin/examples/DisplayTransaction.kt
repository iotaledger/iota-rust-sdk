// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example demonstrates how to print types as human-readable text.
// Most types offer a `toDisplayString()` method; types mirrored from the core
// crate offer a `<type>ToDisplayString()` function instead.

import iota_sdk.*

fun main() {
    try {
        // A sample transaction in base64 format
        val txBytesBase64 =
            "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA="

        val transaction = Transaction.fromBase64(txBytesBase64)
        println(transaction.toDisplayString())

        println(transaction.gasPayment().toDisplayString())

        println(transactionExpirationToDisplayString(transaction.expiration()))
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
