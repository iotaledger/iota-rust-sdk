// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val myAddress =
            Address.fromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

        FaucetClient.newLocalnet().requestAndWaitForFinalized(myAddress, client)

        val validators = client.activeValidators()
        if (validators.data.isEmpty()) {
            throw Exception("no validators found")
        }
        val validator = validators.data[0]

        println("Staking to validator ${validator.name ?: "with no name"}")

        val builder = TransactionBuilder(myAddress).withClient(client)

        builder.stake(PtbArgument.u64(1000000000uL), validator.address)

        val res = builder.dryRun(false)

        if (res.error != null) {
            throw Exception("Failed to stake: ${res.error}")
        }

        println("Stake dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
