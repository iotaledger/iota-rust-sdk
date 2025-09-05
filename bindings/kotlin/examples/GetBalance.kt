// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.GraphQlClient
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()
        val address =
                Address.fromHex(
                        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
                )

        val coins =
                client.coins(
                        address,
                        PaginationFilter(
                                direction = Direction.FORWARD,
                                cursor = null,
                                limit = null
                        ),
                        null // coinType
                )
        for (coin in coins.data) {
            println("ID = 0x${coin.id().toHex()} Balance = ${coin.balance()}")
        }

        val balance = client.balance(address, null)
        println("Total Balance = $balance")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
