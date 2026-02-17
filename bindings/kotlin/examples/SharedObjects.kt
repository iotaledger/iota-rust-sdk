// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package iota.sdk.examples

suspend fun main() {
    println("=== Shared Object Operations Example ===\n")

    // Step 1: Overview
    println("1. Shared Objects Overview:")
    println("   - Accessible by anyone")
    println("   - Concurrent multi-transaction use")
    println("   - Require special handling")
    println("   - Examples: pools, registries\n")

    // Step 2: Comparison
    println("2. Shared vs Owned Objects:")
    println("   Owned Objects:")
    println("     - Single owner controls access")
    println("     - Only owner can use")
    println("     - Simpler transaction handling\n")
    println("   Shared Objects:")
    println("     - No single owner")
    println("     - Anyone can use them")
    println("     - Requires shared references\n")

    // Step 3: Querying
    println("3. Querying Shared Objects:")
    println("   - Use object() to fetch details")
    println("   - Check shared ownership")
    println("   - Identify type and structure\n")

    // Step 4: Transaction patterns
    println("4. Transaction Patterns:")
    println("   a. Move call with shared object")
    println("   b. Multiple shared objects")
    println("   c. Mixing shared and owned")
    println("   d. Concurrency best practices\n")

    // Step 5: Use cases
    println("5. Common Use Cases:")
    println("   - DEX liquidity pools")
    println("   - Shared registries")
    println("   - Governance contracts")
    println("   - Public state\n")

    // Step 6: Best practices
    println("6. Best Practices:")
    println("   - Minimize shared object usage")
    println("   - Design for concurrent access")
    println("   - Handle contention gracefully")
    println("   - Consider gas costs\n")

    println("Shared objects example completed!")
    println("See also: TransactionsWithShared.kt, DynamicFields.kt")
}
