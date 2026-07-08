// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        // Amount to send in nanos
        val amount = 1000uL
        val recipientAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        val privateKey = Ed25519PrivateKey(ByteArray(32))
        val senderAddress = privateKey.publicKey().deriveAddress()
        println("Sender address: ${senderAddress.toHex()}")

        // Request funds from faucet (the faucet client relies on GraphQL to
        // await finalization)
        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWaitForFinalized(senderAddress, GraphQlClient.newLocalnet())

        val client = GrpcClient.newLocalnet()

        // Resolve gas and build the transaction via gRPC
        val builder = TransactionBuilder(senderAddress).withGrpcClient(client)
        builder.sendIota(recipientAddress, PtbArgument.u64(amount))
        val txn = builder.finish()

        val signature = privateKey.trySignSimple(txn.signingDigest())
        val userSignature = UserSignature.newSimple(signature)
        val signedTransaction = SignedTransaction(txn, listOf(userSignature))

        val executed = client.executeTransaction(signedTransaction)

        println("Digest: ${hexEncode(executed.digest!!.toBytes())}")
        println("Transaction status: ${executed.effects!!.asV1().status}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
