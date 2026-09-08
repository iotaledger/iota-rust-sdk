// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val privateKey = Ed25519PrivateKey.random()
        val fromAddress = privateKey.publicKey().deriveAddress()
        val toAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWaitForFinalized(fromAddress, client)

        val coins = client.objects(ObjectFilter(owner = fromAddress)).data
        val gasCoin = coins.first()
        val objsToTransfer = coins.drop(1).map { PtbArgument.objectRef(it.objectRef()) }

        var gasPrice = client.referenceGasPrice()

        val builder = TransactionBuilder(fromAddress)

        builder.transferObjects(toAddress, objsToTransfer)
        builder.gas(listOf(gasCoin.objectRef())).gasPrice(gasPrice ?: 100uL).gasBudget(500000000uL)

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = client.dryRunTransaction(txn)

        if (res.error != null) {
            throw Exception("Failed to transfer objects: ${res.error}")
        }

        println("Transfer objects dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
