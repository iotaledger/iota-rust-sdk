// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.Function
import iota_sdk.GraphQlClient
import iota_sdk.Identifier
import iota_sdk.ObjectFilter
import iota_sdk.ObjectId
import iota_sdk.PaginationFilter
import iota_sdk.StructTag
import iota_sdk.TransactionBuilder
import iota_sdk.UnresolvedInput
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
        try {
                val client = GraphQlClient.newDevnet()

                val stakedIotas =
                        client.objects(
                                PaginationFilter(Direction.FORWARD),
                                ObjectFilter(typeTag = "0x3::staking_pool::StakedIota")
                        )
                if (stakedIotas.data.isEmpty()) {
                        throw Exception("no validators found")
                }
                val stakedIota = stakedIotas.data[0]

                val gasCoins =
                        client.objects(
                                PaginationFilter(Direction.FORWARD),
                                ObjectFilter(
                                        typeTag = StructTag.gasCoin().toString(),
                                        owner = stakedIota.owner().asAddress()
                                )
                        )
                if (gasCoins.data.isEmpty()) {
                        throw Exception("no gas coins found")
                }
                val gasCoin = gasCoins.data[0]

                val builder = TransactionBuilder()
                val inputs =
                        listOf(
                                builder.input(
                                        UnresolvedInput.newShared(ObjectId.fromHex("0x5"), 1u, true)
                                ),
                                builder.input(
                                        UnresolvedInput.fromObject(stakedIota).withOwnedKind()
                                ),
                        )
                builder.moveCall(
                        Function(
                                Address.fromHex("0x3"),
                                Identifier("iota_system"),
                                Identifier("request_withdraw_stake"),
                                emptyList()
                        ),
                        inputs
                )
                builder.setSender(gasCoin.owner().asAddress())
                builder.setGasBudget(50000000u)
                val refGasPrice = client.referenceGasPrice(null)
                if (refGasPrice == null) {
                        throw Exception("missing ref gas price")
                }
                builder.setGasPrice(refGasPrice)
                builder.addGasObjects(listOf(UnresolvedInput.fromObject(gasCoin).withOwnedKind()))

                val txn = builder.finish()
                val res = client.dryRunTx(txn, false)

                if (res.error != null) {
                        throw Exception(res.error)
                }

                println("Successfully unstaked!")
        } catch (e: Exception) {
                e.printStackTrace()
        }
}
