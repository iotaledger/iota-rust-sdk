// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        // Filtering by type alone scans every object on the network, which the GraphQL
        // server rejects with a timeout, so filter by owner as well.
        val owner =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

        val stakedIotas =
            client.objects(
                ObjectFilter(typeTag = StructTag.newStakedIota().toString(), owner = owner)
            )
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
