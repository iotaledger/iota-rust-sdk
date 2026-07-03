// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val stakedIotas =
            client.objects(ObjectFilter(typeTag = StructTag.newStakedIota().toString()))
        if (stakedIotas.data.isEmpty()) {
            throw Exception("no validators found")
        }
        val stakedIota = stakedIotas.data[0]

        val builder = TransactionBuilder(stakedIota.owner().asAddress()).withClient(client)

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
