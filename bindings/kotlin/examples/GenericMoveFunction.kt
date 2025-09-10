// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Function
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.ObjectId
import iota_sdk.TransactionBuilder
import iota_sdk.TypeTag
import iota_sdk.UnresolvedInput
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

        val gasCoin =
                client.`object`(
                        ObjectId.fromHex(
                                "0xa1d009e8dafe20b1cba05e08aea488aafae1f89d892c3eaef6c0994e155e441a"
                        )
                )
                        ?: error("Missing gas coin")

        val builder = TransactionBuilder()

        val address1 =
                builder.input(
                        UnresolvedInput.newPure(
                                Address.fromHex(
                                                "0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e"
                                        )
                                        .toBytes()
                        )
                )
        val address2 =
                builder.input(
                        UnresolvedInput.newPure(
                                Address.fromHex(
                                                "0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3"
                                        )
                                        .toBytes()
                        )
                )

        val balance1 = builder.input(UnresolvedInput.newPure(uLongToBytes(10_000_000uL)))
        val balance2 = builder.input(UnresolvedInput.newPure(uLongToBytes(20_000_000uL)))

        val addresses = builder.makeMoveVec(TypeTag.newAddress(), listOf(address1, address2))
        val balances = builder.makeMoveVec(TypeTag.newU64(), listOf(balance1, balance2))

        val package_addr = Address.fromHex("0x2")
        val module_name = Identifier("vec_map")
        val function_name = Identifier("from_keys_values")

        val function =
                Function(
                        package_addr,
                        module_name,
                        function_name,
                        listOf(TypeTag.newAddress(), TypeTag.newU64())
                )
        builder.moveCall(function, listOf(addresses, balances))

        builder.setSender(sender)
        builder.setGasBudget(50_000_000uL)
        builder.setGasPrice(
                client.referenceGasPrice(null) ?: error("Failed to fetch reference gas price")
        )
        builder.addGasObjects(listOf(UnresolvedInput.fromObject(gasCoin).withOwnedKind()))

        val txn = builder.finish()
        val res = client.dryRunTx(txn, false)

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
