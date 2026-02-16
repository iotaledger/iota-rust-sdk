// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient

/**
 * Example: IOTA Names Operations
 *
 * This example demonstrates major IOTA Names operations.
 */
fun main() {
    val client = GraphQlClient.newDevnet()

    println("=== IOTA Names Example ===")
    println()
    println("1. Resolving name 'name.iota'")
    println("   (Implementation would use TransactionBuilder)")
    println()
    println("2. Checking availability of 'test123.iota'")
    println("   (Implementation would use TransactionBuilder)")
}
