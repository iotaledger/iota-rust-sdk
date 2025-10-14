// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val sender =
                Address.fromHex(
                        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
                )
        val sponsor =
                Address.fromHex(
                        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
                )

        val builder = TransactionBuilder.init(sender, client)

        val packageAddr = Address.stdLib()
        val moduleName = Identifier("u8")
        val functionName = Identifier("max")

        builder.moveCall(
                packageAddr,
                moduleName,
                functionName,
                listOf(PtbArgument.u8(0u), PtbArgument.u8(1u)),
        )

        val gasObjId =
                ObjectId.fromHex(
                        "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
                )
        builder.gas(gasObjId).sponsor(sponsor)

        val txn = builder.finish()

        println("Signing Digest: ${hexEncode(txn.signingDigest())}")
        println("Txn Bytes: ${base64Encode(txn.toBytes())}")

        val res = client.dryRunTx(txn, false)

        if (res.error != null) {
            throw Exception("Failed to send gas sponsor tx: ${res.error}")
        }

        println("Gas sponsor tx dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
