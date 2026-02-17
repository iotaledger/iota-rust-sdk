// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package iota.sdk.examples

import iota.sdk.GraphQlClient

suspend fun main() {
    val client = GraphQlClient.newDevnet()

    println("=== Validator Operations Example ===\n")

    // Step 1: Query validators
    println("1. Querying active validators...")
    val validators = client.activeValidators(null, emptyMap())
    println("   Found ${validators.data.size} active validators\n")

    // Step 2: Display validator information
    println("2. Validator Information:")
    validators.data.take(5).forEachIndexed { idx, validator ->
        println("\n   Validator #${idx + 1}:")
        validator.name?.let { println("     Name: $it") }
        println("     Address: ${validator.address.address}")
        println("     Voting Power: ${validator.votingPower}")

        validator.nextEpochStakeApy?.let { apy ->
            println("     Staking APY: ${"%.2f".format(apy)}%")
        }

        println("     Pending Stake: ${validator.pendingStake} MIST")
        println("     Pending Withdraw: ${validator.pendingWithdraw} MIST")
    }

    // Step 3: Best practices
    println("\n3. Validator Selection Criteria:")
    println("   - Check commission rates")
    println("   - Review voting power distribution")
    println("   - Consider uptime and performance")
    println("   - Evaluate staking APY")
    println("   - Assess community reputation\n")

    // Step 4: Staking workflow
    println("4. Staking Workflow:")
    println("   a. Choose a validator")
    println("   b. Prepare staking transaction")
    println("   c. Sign and submit transaction")
    println("   d. Monitor staking rewards")
    println("   e. Unstake when needed\n")

    println("Validator operations example completed!")
    println("See also: Stake.kt, Unstake.kt")
}
