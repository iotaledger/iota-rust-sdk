// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Send IOTA from a Ledger device's address on a local network. Set
// LEDGER_SIMULATOR to use the Speculos emulator instead of a device.

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    // Amount to send in nanos
    val amount = 1000uL
    val recipientAddress =
        Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    val ledger =
        if (System.getenv("LEDGER_SIMULATOR") != null) {
            Ledger.speculos("127.0.0.1", 9999u)
        } else {
            Ledger.nativeHid()
        }
    ledger.openApp()
    val signer = ledger.signer("m/44'/4218'/0'/0'/0'")
    val senderAddress = signer.address()
    println("Sender address: ${senderAddress}")

    val client = GraphQlClient.newLocalnet()

    // Request funds from faucet
    FaucetClient.newLocalnet().requestAndWaitForFinalized(senderAddress, client)

    val builder = client.transactionBuilder(senderAddress)
    builder.sendIota(recipientAddress, PtbArgument.u64(amount))

    // The builder passes the signer the coins the transaction spends, so the
    // device shows the transfer instead of asking to blind-sign
    println("Review and approve the transaction on the device")
    val effects =
        builder.execute(TransactionSigner.fromLedger(signer), WaitForTransaction.FINALIZED)
    println("Digest: ${effects.digest().toBase58()}")
    println("Transaction status: ${effects.asV1().status()}")
}
