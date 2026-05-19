// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.FaucetClient
import iota_sdk.GraphQlClient
import iota_sdk.hexEncode
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {

        val client = GraphQlClient.newLocalnet()

        val address =
            Address.fromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
        FaucetClient.newLocalnet().requestAndWaitForFinalized(address, client)
        val coins = client.coins(address)
        val objectId =
            coins.data.firstOrNull()?.id()
                ?: throw Exception("address has no coins after faucet request")

        val obj = client.`object`(objectId)!!

        println("Object ID: ${obj.objectId().toHex()}")
        println("Version: ${obj.version()}")
        println("Previous transaction: ${obj.previousTransaction().toBase58()}")
        println("Owner: ${obj.owner().toString()}")
        println("Storage rebate: ${obj.storageRebate()}")
        println("Type: ${obj.objectType().toString()}")
        @OptIn(kotlin.ExperimentalStdlibApi::class)
        println("BCS bytes: ${hexEncode(obj.asStruct().contents)}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
