// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val recipientAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        val signer1 = Ed25519PrivateKey(ByteArray(32))
        val signer2 = Ed25519PrivateKey(ByteArray(32).also { it[0] = 1 })

        val simple1 = SimpleKeypair.fromEd25519(signer1)
        val simple2 = SimpleKeypair.fromEd25519(signer2)

        val committee = MultisigCommittee(
            listOf(
                MultisigMember(simple1.publicKey(), 1u.toUByte()),
                MultisigMember(simple2.publicKey(), 1u.toUByte()),
            ),
            2u.toUShort(),
        )

        if (!committee.isValid()) {
            throw Exception("Multisig committee is invalid")
        }

        val multisigAddress = committee.deriveAddress()
        println("Multisig sender address: ${multisigAddress.toHex()}")

        val client = GraphQlClient.newLocalnet()

        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWaitForFinalized(multisigAddress, client)

        val builder = TransactionBuilder(multisigAddress).withClient(client)
        builder.sendIota(recipientAddress, PtbArgument.u64(1000uL))
        val txn = builder.finish()

        val dryRunResult = client.dryRunTx(txn, false)
        if (dryRunResult.error != null) {
            throw Exception("Dry run failed: ${dryRunResult.error}")
        }

        val sig1 = simple1.signTransaction(txn)
        val sig2 = simple2.signTransaction(txn)

        var aggregator = MultisigAggregator.newWithTransaction(committee, txn)
        aggregator = aggregator.withSignature(sig1)
        aggregator = aggregator.withSignature(sig2)

        val multisigSig = UserSignature.newMultisig(aggregator.finish())
        val effects = client.executeTx(listOf(multisigSig), txn)

        println("Digest: ${hexEncode(effects.digest().toBytes())}")
        println("Transaction status: ${effects.asV1().status}")
        println("Effects: ${effects.asV1()}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
