// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.PtbArgument
import iota_sdk.TransactionBuilder
import iota_sdk.TypeTag
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val sender =
                Address.fromHex(
                        "0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e"
                )

        val builder = TransactionBuilder.init(sender, client)

        val address1 =
                Address.fromHex(
                        "0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e"
                )
        val address2 =
                Address.fromHex(
                        "0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3"
                )

        val package_addr = Address.fromHex("0x2")
        val module_name = Identifier("vec_map")
        val function_name = Identifier("from_keys_values")

        builder.makeMoveVec(
                listOf(PtbArgument.address(address1), PtbArgument.address(address2)),
                TypeTag.newAddress(),
                "addresses"
        )
        builder.makeMoveVec(
                listOf(PtbArgument.u64(10_000_000uL), PtbArgument.u64(20_000_000uL)),
                TypeTag.newU64(),
                "amounts"
        )

        builder.moveCall(
                package_addr,
                module_name,
                function_name,
                listOf(
                        PtbArgument.res("addresses"),
                        PtbArgument.res("amounts"),
                )
        )

        val res = builder.dryRun(true)

        if (res.error != null) {
            println("Failed to call generic Move function: $res.error")
        }

        println("Successfully called generic Move function!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}

fun uLongToBytes(num: ULong): ByteArray {
    return ByteBuffer.allocate(ULong.SIZE_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(num.toLong())
            .array()
}
