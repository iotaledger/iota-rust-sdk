// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct SignSendIotaExample {
  static func main() async throws {
    // Amount to send in nanos
    let amount: UInt64 = 1000
    let recipientAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    let privateKey = try Ed25519PrivateKey(bytes: Data(repeating: 0, count: 32))
    let publicKey = privateKey.publicKey()
    let senderAddress = publicKey.deriveAddress()
    print("Sender address: \(senderAddress.toHex())")

    let client = GraphQlClient.newLocalnet()

    // Request funds from faucet
    let faucet = FaucetClient.newLocalnet()
    _ = try await faucet.requestAndWaitForFinalized(address: senderAddress, client: client)

    let builder = client.transactionBuilder(sender: senderAddress)
    _ = builder.sendIota(recipient: recipientAddress, amount: PtbArgument.u64(value: amount))
    let txn = try await builder.finish()

    let dryRunResult = try await client.dryRunTx(tx: txn)
    if dryRunResult.error != nil {
      throw NSError(
        domain: "SignSendIota", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: \(dryRunResult.error!)"])
    }

    let signature = try privateKey.trySignSimple(message: txn.signingDigest())
    let userSignature = UserSignature.newSimple(signature: signature)

    let effects = try await client.executeTx(signatures: [userSignature], tx: txn)

    print("Digest: \(hexEncode(input: effects.digest().toBytes()))")
    print("Transaction status: \(effects.asV1().status)")
    print("Effects: \(effects.asV1())")
  }
}
