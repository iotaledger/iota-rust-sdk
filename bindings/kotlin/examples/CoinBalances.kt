// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.FaucetClient
import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()
        val address =
            Address.fromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
        FaucetClient.newLocalnet().requestAndWaitForFinalized(address, client)

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
