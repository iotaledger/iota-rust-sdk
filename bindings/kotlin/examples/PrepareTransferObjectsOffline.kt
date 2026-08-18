// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val fromAddress =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
        val toAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
        val objects =
            listOf(
                ObjectId.fromHex(
                    "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db"
                ),
                ObjectId.fromHex(
                    "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc"
                ),
                ObjectId.fromHex(
                    "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2"
                ),
            )
        val objsToTransfer = objects.map {
            val obj = client.`object`(it)
            if (obj == null) {
                throw Exception("Missing object: ${it}")
            }
            PtbArgument.objectRef(obj.objectRef())
        }
        val gasCoinId =
            ObjectId.fromHex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")
        val gasCoin = client.`object`(gasCoinId)
        if (gasCoin == null) {
            throw Exception("Missing gas coin: ${gasCoinId}")
        }
        var gasPrice = client.referenceGasPrice()

        val builder = TransactionBuilder(fromAddress)

        builder.transferObjects(toAddress, objsToTransfer)
        builder.gas(listOf(gasCoin.objectRef())).gasPrice(gasPrice ?: 100uL).gasBudget(500000000uL)

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = client.dryRunTx(txn)

        if (res.error != null) {
            throw Exception("Failed to transfer objects: ${res.error}")
        }

        println("Transfer objects dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
