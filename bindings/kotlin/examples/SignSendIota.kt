// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        // Amount to send in nanos
        val amount = 1000uL
        val recipientAddress =
                Address.fromHex(
                        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
                )

        val privateKey = Ed25519PrivateKey(ByteArray(32))
        val publicKey = privateKey.publicKey()
        val senderAddress = publicKey.deriveAddress()
        println("Sender address: ${senderAddress.toHex()}")

        // Request funds from faucet
        val faucet = FaucetClient.newLocal()
        faucet.requestAndWait(senderAddress)

        val client = GraphQlClient.newLocalhost()
        // Get coins for the sender address
        val coinsPage = client.coins(senderAddress, null, null)
        if (coinsPage.data.isEmpty()) {
            throw Exception("No coins found")
        }
        val gasCoin = coinsPage.data[0]

        val builder = TransactionBuilder.init(senderAddress, client)

        // Split the amount from the gas coin
        builder.splitCoins(gasCoin.id(), listOf(amount), listOf("coin1"))

        // Transfer the split coin
        builder.transferObjects(recipientAddress, listOf(PtbArgument.res("coin1")))

        builder.gas(gasCoin.id()).gasBudget(50000000.toULong())
        val gasPrice = client.referenceGasPrice(null)
        if (gasPrice == null) {
            throw Exception("Failed to get gas price")
        }
        builder.gasPrice(gasPrice)

        val txn = builder.finish()

        val dryRunResult = client.dryRunTx(txn, false)
        if (dryRunResult.error != null) {
            throw Exception("Dry run failed: ${dryRunResult.error}")
        }

        val signature = privateKey.trySignSimple(txn.signingDigest())
        val userSignature = UserSignature.newSimple(signature)

        val effects = client.executeTx(listOf(userSignature), txn)
        if (effects == null) {
            throw Exception("Transaction execution failed")
        }
        println("Digest: ${hexEncode(effects.digest().toBytes())}")
        println("Transaction status: ${effects.asV1().status}")
        println("Effects: ${effects.asV1()}")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
