// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.ObjectFilter
import iota_sdk.ObjectId
import iota_sdk.PtbArgument
import iota_sdk.StructTag
import iota_sdk.TransactionBuilder
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val stakedIotas = client.objects(ObjectFilter(typeTag = "0x3::staking_pool::StakedIota"))
        if (stakedIotas.data.isEmpty()) {
            throw Exception("no validators found")
        }
        val stakedIota = stakedIotas.data[0]

        val gasCoins =
                client.objects(
                        ObjectFilter(
                                typeTag = StructTag.gasCoin().toString(),
                                owner = stakedIota.owner().asAddress()
                        )
                )
        if (gasCoins.data.isEmpty()) {
            throw Exception("no gas coins found")
        }
        val gasCoin = gasCoins.data[0]

        val builder = TransactionBuilder.init(gasCoin.owner().asAddress(), client)

        builder.moveCall(
                Address.fromHex("0x3"),
                Identifier("iota_system"),
                Identifier("request_withdraw_stake"),
                listOf(
                        PtbArgument.mutable(ObjectId.fromHex("0x5")),
                        PtbArgument.objectId(stakedIota.objectId())
                ),
        )
        builder.gas(gasCoin.objectId()).gasBudget(1000000000uL)

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception(res.error)
        }

        println("Unstake dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
