// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.EventFilter
import iota_sdk.GraphQlClient
import iota_sdk.ObjectId
import iota_sdk.PaginationFilter
import iota_sdk.TransactionsFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val myAddress =
                Address.fromHex(
                        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
                )

        val coins = client.coins(myAddress)
        for (coin in coins.data) {
            println("ID = 0x${coin.id().toHex()} Balance = ${coin.balance()}")
        }

        val balance = client.balance(myAddress, null)
        println("Total Balance = $balance")

        val _txFilter =
                TransactionsFilter(
                        atCheckpoint = 3UL,
                        inputObject =
                                ObjectId.fromHex(
                                        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
                                ),
                        // ...other fields as needed
                        )

        val _eventFilter =
                EventFilter(
                        sender = myAddress
                        // ...other fields as needed
                        )
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
