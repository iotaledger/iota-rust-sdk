// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

class AsyncSigner(val key: Ed25519PrivateKey) : SignerFn {
    override suspend fun sign(transaction: Transaction): SignerFnOutput {
        return SignerFnOutput(key.signTransaction(transaction))
    }
}

fun main() = runBlocking {
    try {
        // Amount to send in nanos
        val amount = 1000uL
        val recipientAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        val privateKey = Ed25519PrivateKey(ByteArray(32))
        val publicKey = privateKey.publicKey()
        val senderAddress = publicKey.deriveAddress()
        println("Sender address: ${senderAddress.toHex()}")

        

        val signer = Signer(AsyncSigner(privateKey))

        // Request funds from faucet
        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWait(senderAddress)

        val client = GraphQlClient.newLocalnet()

        val builder = TransactionBuilder(senderAddress).withClient(client)
        builder.sendIota(recipientAddress, PtbArgument.u64(amount))

        val effects = builder.execute(signer, WaitForTx.FINALIZED)

        println("Digest: ${hexEncode(effects.digest().toBytes())}")
        println("Transaction status: ${effects.asV1().status}")
        println("Effects: ${effects.asV1()}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
