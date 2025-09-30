// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Function
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.ObjectId
import iota_sdk.StructTag
import iota_sdk.TransactionBuilder
import iota_sdk.TypeTag
import iota_sdk.UnresolvedInput
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val senderAddress = Address.fromHex("0x0")

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

        val builder = TransactionBuilder()

        // Create identifiers
        val iotaNamesModule = Identifier("iota_names")
        val registryFn = Identifier("registry")
        val nameModule = Identifier("name")
        val newFn = Identifier("new")
        val lookupFn = Identifier("lookup")
        val optionModule = Identifier("option")
        val borrowFn = Identifier("borrow")
        val nameRecordModule = Identifier("name_record")
        val targetAddressFn = Identifier("target_address")

        // Create type tags
        val registryName = Identifier("Registry")
        val registryType = StructTag(iotaNamesPackageAddress, registryFn, registryName, listOf())

        val nameRecordName = Identifier("NameRecord")
        val nameRecordType =
                StructTag(iotaNamesPackageAddress, nameRecordModule, nameRecordName, listOf())

        // 1. Get the registry
        val registryInput =
                builder.input(UnresolvedInput.newShared(iotaNamesObjectId, 365644877u, true))
        val iotaNames =
                builder.moveCall(
                        Function(
                                iotaNamesPackageAddress,
                                iotaNamesModule,
                                registryFn,
                                listOf(TypeTag.newStruct(registryType))
                        ),
                        listOf(registryInput)
                )

        // 2. Create name from string
        // BCS encode the string: length (as varint) + UTF-8 bytes
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val nameLen = nameBytes.size
        val bcsEncodedName =
                if (nameLen < 128) {
                    // For strings shorter than 128 bytes, length is encoded as single byte
                    byteArrayOf(nameLen.toByte()) + nameBytes
                } else {
                    // For longer strings, we'd need proper varint encoding
                    // but for this example, the name should be short
                    throw Exception("String too long for simple BCS encoding")
                }
        val nameInput = builder.input(UnresolvedInput.newPure(bcsEncodedName))
        val nameResult =
                builder.moveCall(
                        Function(iotaNamesPackageAddress, nameModule, newFn, listOf()),
                        listOf(nameInput)
                )

        // 3. Lookup name record
        val nameRecordOption =
                builder.moveCall(
                        Function(iotaNamesPackageAddress, registryFn, lookupFn, listOf()),
                        listOf(iotaNames, nameResult)
                )

        // 4. Borrow name record from option
        val nameRecord =
                builder.moveCall(
                        Function(
                                stdlibAddress,
                                optionModule,
                                borrowFn,
                                listOf(TypeTag.newStruct(nameRecordType))
                        ),
                        listOf(nameRecordOption)
                )

        // 5. Get target address from name record
        val targetAddressOption =
                builder.moveCall(
                        Function(
                                iotaNamesPackageAddress,
                                nameRecordModule,
                                targetAddressFn,
                        ),
                        listOf(nameRecord)
                )

        // 6. Borrow address from option
        builder.moveCall(
                Function(stdlibAddress, optionModule, borrowFn, listOf(TypeTag.newAddress())),
                listOf(targetAddressOption)
        )

        builder.setSender(senderAddress)
        builder.setGasBudget(50000000u)
        val gasPrice = client.referenceGasPrice(null)
        if (gasPrice == null) {
            throw Exception("Missing reference gas price")
        }
        builder.setGasPrice(gasPrice)

        val txn = builder.finish()

        val res = client.dryRunTx(txn, true)

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
