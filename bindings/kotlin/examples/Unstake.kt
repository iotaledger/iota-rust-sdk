// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val stakedIotas =
            client.objects(ObjectFilter(typeTag = StructTag.newStakedIota().toString()))
        if (stakedIotas.data.isEmpty()) {
            throw Exception("no staked iota found")
        }
        val stakedIota = stakedIotas.data[0]
        val staker = stakedIota.owner().asAddress()

        val builder = TransactionBuilder(staker).withClient(client)
        builder.unstake(PtbArgument.objectId(stakedIota.objectId()))

        val res = builder.dryRun(false)

        if (res.error != null) {
            throw Exception(res.error)
        }

        println("Unstake dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
