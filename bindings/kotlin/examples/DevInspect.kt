// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.ObjectId
import iota_sdk.PtbArgument
import iota_sdk.StructTag
import iota_sdk.TransactionBuilder
import iota_sdk.TypeTag
import kotlin.collections.emptyList
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val sender = Address.fromHex("0x0")

        val iotaNamesPackageAddress =
                Address.fromHex(
                        "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba"
                )
        val iotaNamesObjectId =
                ObjectId.fromHex(
                        "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
                )
        val stdlibAddress = Address.fromHex("0x1")

        val name = "name.iota"
        println("Looking up name: $name")

        val builder = TransactionBuilder.init(sender, client)

        // 1. Get the registry
        builder.moveCall(
                iotaNamesPackageAddress,
                Identifier("iota_names"),
                Identifier("registry"),
                listOf(PtbArgument.mutable(iotaNamesObjectId)),
                listOf(
                        TypeTag.newStruct(
                                StructTag(
                                        iotaNamesPackageAddress,
                                        Identifier("registry"),
                                        Identifier("Registry"),
                                )
                        )
                ),
                listOf("iota_names")
        )

        // 2. Create name from string
        // BCS encode the string: length (as varint) + UTF-8 bytes
        builder.moveCall(
                iotaNamesPackageAddress,
                Identifier("name"),
                Identifier("new"),
                listOf(PtbArgument.string(name)),
                emptyList(),
                listOf("name")
        )

        // 3. Lookup name record
        builder.moveCall(
                iotaNamesPackageAddress,
                Identifier("registry"),
                Identifier("lookup"),
                listOf(PtbArgument.res("iota_names"), PtbArgument.res("name")),
                emptyList(),
                listOf("name_record_opt")
        )

        // 4. Borrow name record from option
        builder.moveCall(
                stdlibAddress,
                Identifier("option"),
                Identifier("borrow"),
                listOf(PtbArgument.res("name_record_opt")),
                listOf(
                        TypeTag.newStruct(
                                StructTag(
                                        iotaNamesPackageAddress,
                                        Identifier("name_record"),
                                        Identifier("NameRecord"),
                                )
                        )
                ),
                listOf("name_record")
        )

        // 5. Get target address from name record
        builder.moveCall(
                iotaNamesPackageAddress,
                Identifier("name_record"),
                Identifier("target_address"),
                listOf(PtbArgument.res("name_record")),
                emptyList(),
                listOf("target_address_opt")
        )

        // 6. Borrow address from option
        builder.moveCall(
                stdlibAddress,
                Identifier("option"),
                Identifier("borrow"),
                listOf(PtbArgument.res("target_address_opt")),
                listOf(TypeTag.newAddress()),
                listOf("target_address")
        )

        val res = builder.dryRun(true)

        if (res.error != null) {
            throw Exception("Failed to lookup name: ${res.error}")
        }

        // Extract the resolved address from the last result
        if (res.results.isNotEmpty()) {
            val lastEffect = res.results.last()
            if (lastEffect.returnValues.isNotEmpty()) {
                val returnValue = lastEffect.returnValues.first()
                if (returnValue.typeTag.isAddress() && returnValue.bcs.size == 32) {
                    val resolvedAddress = Address.fromBytes(returnValue.bcs)
                    println("Resolved address: ${resolvedAddress.toHex()}")
                } else {
                    println(
                            "Last result is not an address type or has wrong length: ${returnValue.bcs.size}"
                    )
                }
            } else {
                println("No return value in last effect")
            }
        } else {
            println("No results found")
        }
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
