// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.FaucetClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val address =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
        val faucetClient = FaucetClient.newLocalnet()
        val faucetReceipt = faucetClient.requestAndWait(address)
        if (faucetReceipt != null) {
            println("Faucet receipt:")
            for (coin in faucetReceipt.sent) {
                println(
                    "  Coin ID: ${coin.id.toHex()}, Amount: ${coin.amount}, Digest: ${coin.transferTxDigest.toBase58()}"
                )
            }
        } else {
            println("Faucet receipt: null")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
