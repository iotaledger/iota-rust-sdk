// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// 2-of-3 Ed25519 multisig example.
//
// Derives 3 keypairs from a mnemonic at indices 0, 1, 2, creates a multisig
// committee with threshold 2, funds the multisig address via faucet, builds
// a send_iota transaction, signs with only 2 of the 3 keys, aggregates,
// and executes.
//
// Requires a running localnet (`iota start --force-regenesis`).

import iota_sdk.*
import kotlinx.coroutines.runBlocking

const val MULTISIG_MNEMONIC =
    "round attack kitchen wink winter music trip tiny nephew hire orange what"

fun main() = runBlocking {
    try {
        val amount = 1000uL
        val recipientAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        // 1. Derive 3 Ed25519 keypairs from mnemonic at indices 0, 1, 2
        val key0 = Ed25519PrivateKey.fromMnemonic(MULTISIG_MNEMONIC, 0uL)
        val key1 = Ed25519PrivateKey.fromMnemonic(MULTISIG_MNEMONIC, 1uL)
        val key2 = Ed25519PrivateKey.fromMnemonic(MULTISIG_MNEMONIC, 2uL)

        // 2. Get MultisigMemberPublicKey via SimpleKeypair
        val kp0 = SimpleKeypair.fromEd25519(key0)
        val kp1 = SimpleKeypair.fromEd25519(key1)
        val kp2 = SimpleKeypair.fromEd25519(key2)

        // 3. Build multisig committee: threshold=2, each member weight=1
        val committee =
            MultisigCommittee(
                listOf(
                    MultisigMember(kp0.publicKey(), 1u),
                    MultisigMember(kp1.publicKey(), 1u),
                    MultisigMember(kp2.publicKey(), 1u),
                ),
                2u,
            )

        // 4. Derive multisig address
        val multisigAddress = committee.deriveAddress()
        println("Multisig address: ${multisigAddress.toHex()}")

        val client = GraphQlClient.newLocalnet()

        // 5. Fund the multisig address
        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWaitForFinalized(multisigAddress, client)

        // 6. Build a send_iota transaction
        val builder = client.transactionBuilder(multisigAddress)
        builder.sendIota(recipientAddress, PtbArgument.u64(amount))
        val txn = builder.finish()

        val dryRunResult = client.dryRunTx(txn, false)
        if (dryRunResult.error != null) {
            throw Exception("Dry run failed: ${dryRunResult.error}")
        }

        // 7. Sign with key0 and key1 (2-of-3 threshold)
        val sig0 = kp0.signTransaction(txn)
        val sig1 = kp1.signTransaction(txn)

        // 8. Aggregate signatures
        var aggregator = MultisigAggregator.newWithTransaction(committee, txn)
        aggregator = aggregator.withSignature(sig0)
        aggregator = aggregator.withSignature(sig1)
        val aggSig = aggregator.finish()

        // 9. Execute
        val userSignature = UserSignature.newMultisig(aggSig)
        val effects = client.executeTx(listOf(userSignature), txn)

        println("Digest: ${hexEncode(effects.digest().toBytes())}")
        println("Transaction status: ${effects.asV1().status}")
        println("Effects: ${effects.asV1()}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
