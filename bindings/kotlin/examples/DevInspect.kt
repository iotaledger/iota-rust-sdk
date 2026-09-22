// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlin.collections.emptyList
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val sender = Address.zero()

        val iotaNamesPackageAddress =
            Address.fromHex("0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea")
        val iotaNamesObjectId =
            ObjectId.fromHex("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")
        val stdAddress = Address.std()

        val name = "name.iota"
        println("Looking up name: $name")

        val builder = client.transactionBuilder(sender)

        // 1. Get the registry
        builder.moveCall(
            iotaNamesPackageAddress,
            Identifier("iota_names"),
            Identifier("registry"),
            listOf(PtbArgument.sharedMut(iotaNamesObjectId)),
            listOf(
                TypeTag.newStruct(
                    StructTag(
                        iotaNamesPackageAddress,
                        Identifier("registry"),
                        Identifier("Registry"),
                    )
                )
            ),
            listOf("iota_names"),
        )

        // 2. Create name from string
        // BCS encode the string: length (as varint) + UTF-8 bytes
        builder.moveCall(
            iotaNamesPackageAddress,
            Identifier("name"),
            Identifier("new"),
            listOf(PtbArgument.string(name)),
            emptyList(),
            listOf("name"),
        )

        // 3. Lookup name record
        builder.moveCall(
            iotaNamesPackageAddress,
            Identifier("registry"),
            Identifier("lookup"),
            listOf(PtbArgument.assigned("iota_names"), PtbArgument.assigned("name")),
            emptyList(),
            listOf("name_record_opt"),
        )

        // 4. Borrow name record from option
        builder.moveCall(
            stdAddress,
            Identifier("option"),
            Identifier("borrow"),
            listOf(PtbArgument.assigned("name_record_opt")),
            listOf(
                TypeTag.newStruct(
                    StructTag(
                        iotaNamesPackageAddress,
                        Identifier("name_record"),
                        Identifier("NameRecord"),
                    )
                )
            ),
            listOf("name_record"),
        )

        // 5. Get target address from name record
        builder.moveCall(
            iotaNamesPackageAddress,
            Identifier("name_record"),
            Identifier("target_address"),
            listOf(PtbArgument.assigned("name_record")),
            emptyList(),
            listOf("target_address_opt"),
        )

        // 6. Borrow address from option
        builder.moveCall(
            stdAddress,
            Identifier("option"),
            Identifier("borrow"),
            listOf(PtbArgument.assigned("target_address_opt")),
            listOf(TypeTag.newAddress()),
            listOf("target_address"),
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
        kotlin.system.exitProcess(1)
    }
}
