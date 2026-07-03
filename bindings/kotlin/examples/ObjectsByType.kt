// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.ObjectFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val stakedIotas = client.objects(ObjectFilter(typeTag = "0x3::staking_pool::StakedIota"))

        if (stakedIotas.data.isEmpty()) {
            println("No StakedIota objects found")
        } else {
            println("StakedIota object IDs:")
            for (stakedIota in stakedIotas.data) {
                println(stakedIota.id().toHex())
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
