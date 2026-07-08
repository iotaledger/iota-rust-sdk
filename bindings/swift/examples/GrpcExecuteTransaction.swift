// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct GrpcExecuteTransactionExample {
  static func main() async throws {
    // Amount to send in nanos
    let amount: UInt64 = 1000
    let recipientAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    let privateKey = try Ed25519PrivateKey(bytes: Data(repeating: 0, count: 32))
    let senderAddress = privateKey.publicKey().deriveAddress()
    print("Sender address: \(senderAddress.toHex())")

    // Request funds from faucet (the faucet client relies on GraphQL to await
    // finalization)
    let faucet = FaucetClient.newLocalnet()
    _ = try await faucet.requestAndWaitForFinalized(
      address: senderAddress, client: GraphQlClient.newLocalnet())

    let client = try GrpcClient.newLocalnet()

    // Resolve gas and build the transaction via gRPC
    let builder = TransactionBuilder(sender: senderAddress).withGrpcClient(client: client)
    _ = builder.sendIota(recipient: recipientAddress, amount: PtbArgument.u64(value: amount))
    let txn = try await builder.finish()

    let signature = try privateKey.trySignSimple(message: txn.signingDigest())
    let userSignature = UserSignature.newSimple(signature: signature)
    let signedTransaction = SignedTransaction(transaction: txn, signatures: [userSignature])

    let executed = try await client.executeTransaction(signedTransaction: signedTransaction)

    print("Digest: \(hexEncode(input: executed.digest!.toBytes()))")
    print("Transaction status: \(executed.effects!.asV1().status)")
  }
}
