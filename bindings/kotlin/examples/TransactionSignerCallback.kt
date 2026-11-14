// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

// A signer implemented in the host language. This one wraps a local key, which
// needs nothing but the transaction, so it opts out of the objects the builder
// fetches for a signer that shows the transaction to its user, such as a
// hardware wallet.
class AsyncSigner(val key: Ed25519PrivateKey) : TransactionSignerFn {
    override suspend fun sign(transaction: Transaction): TransactionSignerFnOutput {
        return TransactionSignerFnOutput(key.signTransaction(transaction))
    }

    override fun usesObjects(): Boolean = false

    // Never called for a signer whose `usesObjects` returns false; the
    // interface still requires it.
    override suspend fun signWithObjects(
        transaction: Transaction,
        objects: List<Object>,
    ): TransactionSignerFnOutput = sign(transaction)
}

fun main() = runBlocking {
    try {
        val amount = 1000uL
        val recipientAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        val privateKey = Ed25519PrivateKey(ByteArray(32))
        val publicKey = privateKey.publicKey()
        val senderAddress = publicKey.deriveAddress()
        println("Sender address: ${senderAddress}")

        val client = GraphQlClient.newLocalnet()

        // Request funds from faucet
        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWaitForFinalized(senderAddress, client)

        val builder = client.transactionBuilder(senderAddress)
        builder.sendIota(recipientAddress, PtbArgument.u64(amount))

        val signer = TransactionSigner(AsyncSigner(privateKey))
        val effects = builder.execute(signer, WaitForTransaction.FINALIZED)

        println("Digest: ${hexEncode(effects.digest().toBytes())}")
        println("Transaction status: ${effects.asV1().status()}")
        println("Effects: ${effects.asV1()}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
