// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val sender =
            Address.fromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

        FaucetClient.newLocalnet().requestAndWaitForFinalized(sender, client)

        val builder = TransactionBuilder(sender).withClient(client)

        val address1 =
            Address.fromHex("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")
        val address2 =
            Address.fromHex("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")

        val package_addr = Address.framework()
        val module_name = Identifier("vec_map")
        val function_name = Identifier("from_keys_values")

        builder.moveCall(
            package_addr,
            module_name,
            function_name,
            listOf(
                PtbArgument.addressVec(listOf(address1, address2)),
                PtbArgument.u64Vec(listOf(10_000_000uL, 20_000_000uL)),
            ),
            listOf(TypeTag.newAddress(), TypeTag.newU64()),
        )

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to call generic Move function: ${res.error}")
        }

        println("Successfully called generic Move function!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
