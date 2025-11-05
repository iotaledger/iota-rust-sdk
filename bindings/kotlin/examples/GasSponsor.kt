// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
  try {
    val client = GraphQlClient.newDevnet()

    val sender =
        Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    val sponsor =
        Address.fromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

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

    builder.sponsor(sponsor)

    val txn = builder.finish()

    println("Signing Digest: ${txn.signingDigestHex()}")
    println("Txn Bytes: ${txn.toBase64()}")

    val res = client.dryRunTx(txn, false)

    if (res.error != null) {
      throw Exception("Failed to send gas sponsor tx: ${res.error}")
    }

    println("Gas sponsor tx dry run was successful!")
  } catch (e: Exception) {
    e.printStackTrace()
    kotlin.system.exitProcess(1)
  }
}
