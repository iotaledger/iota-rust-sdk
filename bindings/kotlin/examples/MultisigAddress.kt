// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import java.util.Base64
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()
        val faucet = FaucetClient.newLocalnet()

        val recipient =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
        val amount = 1000uL

        // Demo keys. Do not use fixed keys like this in production.
        val key1 = Ed25519PrivateKey(ByteArray(32) { 1 })
        val key2 = Ed25519PrivateKey(ByteArray(32) { 2 })

        val pk1B64 = Base64.getEncoder().encodeToString(key1.publicKey().toBytes())
        val pk2B64 = Base64.getEncoder().encodeToString(key2.publicKey().toBytes())

        val mpk1 = multisigMemberPublicKeyFromJson("""{"scheme":"ed25519","public_key":"$pk1B64"}""")
        val mpk2 = multisigMemberPublicKeyFromJson("""{"scheme":"ed25519","public_key":"$pk2B64"}""")

        val committee = MultisigCommittee(
            listOf(
                MultisigMember(mpk1, 1u),
                MultisigMember(mpk2, 1u),
            ),
            2u,
        )

        val multisigAddress = committee.deriveAddress()
        println("Multisig address: ${multisigAddress.toHex()}")

        faucet.requestAndWaitForFinalized(multisigAddress, client)

        val builder = TransactionBuilder(multisigAddress).withClient(client)
        builder.sendIota(recipient, PtbArgument.u64(amount))
        val txn = builder.finish()

        val dryRun = client.dryRunTx(txn, false)
        if (dryRun.error != null) {
            throw Exception("Dry run failed: ${dryRun.error}")
        }

        val sig1 = UserSignature.newSimple(key1.trySignSimple(txn.signingDigest()))
        val sig2 = UserSignature.newSimple(key2.trySignSimple(txn.signingDigest()))

        var aggregator = MultisigAggregator.newWithTransaction(committee, txn)
        aggregator = aggregator.withSignature(sig1)
        aggregator = aggregator.withSignature(sig2)
        val aggSig = aggregator.finish()

        val msUserSig = UserSignature.newMultisig(aggSig)
        val effects = client.executeTx(listOf(msUserSig), txn)

        println("Digest: ${hexEncode(effects.digest().toBytes())}")
        println("Status: ${effects.asV1().status}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
