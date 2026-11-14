// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

// A signer implemented in the host language. This one wraps a local key, which
// needs nothing but the transaction, so it opts out of the objects the builder
// fetches for a signer that shows the transaction to its user, such as a
// hardware wallet.
final class AsyncSigner: TransactionSignerFn, @unchecked Sendable {
  let key: Ed25519PrivateKey

  init(key: Ed25519PrivateKey) {
    self.key = key
  }

  func sign(transaction: Transaction) async throws -> TransactionSignerFnOutput {
    return TransactionSignerFnOutput(signature: try key.signTransaction(transaction: transaction))
  }

  func usesObjects() -> Bool {
    return false
  }

  // Never called for a signer whose `usesObjects` returns false; the
  // interface still requires it.
  func signWithObjects(transaction: Transaction, objects: [Object]) async throws
    -> TransactionSignerFnOutput
  {
    return try await sign(transaction: transaction)
  }
}

@main
struct TransactionSignerCallbackExample {
  static func main() async throws {
    let amount: UInt64 = 1000
    let recipientAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    let privateKey = try Ed25519PrivateKey(bytes: Data(repeating: 0, count: 32))
    let publicKey = privateKey.publicKey()
    let senderAddress = publicKey.deriveAddress()
    print("Sender address: \(senderAddress)")

    let client = try GraphQlClient.newLocalnet()

    // Request funds from faucet
    let faucet = FaucetClient.newLocalnet()
    _ = try await faucet.requestAndWaitForFinalized(address: senderAddress, client: client)

    let builder = client.transactionBuilder(sender: senderAddress)
    _ = builder.sendIota(recipient: recipientAddress, amount: PtbArgument.u64(value: amount))

    let signer = TransactionSigner(signerFn: AsyncSigner(key: privateKey))
    let effects = try await builder.execute(signer: signer, waitFor: WaitForTransaction.finalized)

    print("Digest: \(hexEncode(input: effects.digest().toBytes()))")
    print("Transaction status: \(effects.asV1().status())")
    print("Effects: \(effects.asV1())")
  }
}
