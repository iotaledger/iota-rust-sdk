// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

const val THRESHOLD = 2
const val WEIGHT = 1

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        println("=== Multisig Address Example ===\n")

        // Step 1: Create key pairs
        println("1. Creating key pairs...")
        val publicKeys = emptyList<Any>() // Would contain real keys
        println("   Generated ${publicKeys.size} public keys\n")

        // Step 2: Create multisig address
        println("2. Creating multisig address...")
        println("   Threshold: $THRESHOLD out of 3")
        println("   Multisig address: (would be computed)\n")

        // Step 3: Usage info
        println("3. Multisig Operations:")
        println("   - Requires $THRESHOLD signatures to spend")
        println("   - Each key weight: $WEIGHT")
        println("   - Total weight needed: ${THRESHOLD * WEIGHT}\n")

        // Step 4: Signing process
        println("4. Transaction Signing:")
        println("   a. Create unsigned transaction")
        println("   b. Sign with required keys")
        println("   c. Combine signatures")
        println("   d. Submit transaction\n")

        println("Multisig example completed!")

    } catch (e: Exception) {
        e.printStackTrace()
    }
}
