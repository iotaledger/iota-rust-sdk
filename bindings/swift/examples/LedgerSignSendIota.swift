// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Send IOTA from a Ledger device's address on a local network. Set
// LEDGER_SIMULATOR to use the Speculos emulator instead of a device.

import Foundation
import IotaSDK

@main
struct LedgerSignSendIotaExample {
  static func main() async throws {
    // Amount to send in nanos
    let amount: UInt64 = 1000
    let recipientAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    let ledger =
      ProcessInfo.processInfo.environment["LEDGER_SIMULATOR"] != nil
      ? Ledger.speculos(host: "127.0.0.1", port: 9999)
      : try Ledger.nativeHid()
    try await ledger.openApp()
    let signer = try await ledger.intoSigner(path: "m/44'/4218'/0'/0'/0'")
    let senderAddress = signer.address()
    print("Sender address: \(senderAddress)")

    let client = try GraphQlClient.newLocalnet()

    // Request funds from faucet
    let faucet = FaucetClient.newLocalnet()
    _ = try await faucet.requestAndWaitForFinalized(address: senderAddress, client: client)

    let builder = client.transactionBuilder(sender: senderAddress)
    _ = builder.sendIota(recipient: recipientAddress, amount: PtbArgument.u64(value: amount))

    // The builder passes the signer the coins the transaction spends, so the
    // device shows the transfer instead of asking to blind-sign
    print("Review and approve the transaction on the device")
    let effects = try await builder.execute(
      signer: TransactionSigner.fromLedger(signer: signer), waitFor: WaitForTransaction.finalized)

    print("Digest: \(hexEncode(input: effects.digest().toBytes()))")
    print("Transaction status: \(effects.asV1().status())")
  }
}
