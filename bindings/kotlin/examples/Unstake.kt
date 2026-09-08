// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val privateKey = Ed25519PrivateKey.random()
        val owner = privateKey.publicKey().deriveAddress()

        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWaitForFinalized(owner, client)

        // Stake to get a StakedIota object that can be unstaked
        val validators = client.activeValidators()
        if (validators.data.isEmpty()) {
            throw Exception("no validators found")
        }
        val stakeBuilder = client.transactionBuilder(owner)
        stakeBuilder.stake(PtbArgument.u64(1000000000uL), validators.data[0].address)
        val stakeTx = stakeBuilder.finish()
        val signature = privateKey.trySignSimple(stakeTx.signingDigest())
        client.executeTransaction(
            listOf(UserSignature.newSimple(signature)),
            stakeTx,
            WaitForTransaction.FINALIZED,
        )

        // Unstake
        val stakedIotas =
            client.objects(
                ObjectFilter(typeTag = StructTag.newStakedIota().toString(), owner = owner)
            )
        if (stakedIotas.data.isEmpty()) {
            throw Exception("no staked iotas found")
        }
        val stakedIota = stakedIotas.data[0]

        val builder = client.transactionBuilder(stakedIota.owner().asAddress())

        builder.unstake(PtbArgument.objectId(stakedIota.id()))

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception(res.error)
        }

        println("Unstake dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
