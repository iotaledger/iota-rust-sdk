// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()
        val address =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

        val coins = client.coins(address)
        for (coin in coins.data) {
            println(
                "Coin = 0x${coin.id().toHex()}, Coin Type = ${coin.coinType().asStructTag()}, Balance = ${coin.balance()}"
            )
        }

        val balance = client.balance(address) ?: 0uL
        println("Total Balance = $balance")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
