// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GrpcClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GrpcClient.newTestnet()

        val info = client.getServiceInfo()
        println("Chain ID: ${info.chainId}")
        println("Epoch: ${info.epoch}")
        println("Checkpoint height: ${info.checkpointHeight}")

        val gasPrice = client.getReferenceGasPrice()
        println("Reference gas price: $gasPrice")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
