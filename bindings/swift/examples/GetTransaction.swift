// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GetTransactionExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()
    let digest = try TransactionDigest.fromBase58(
      base58: "3wN9oLKfvCjCd7uFW1D6fp1uSEsD3wJ2cU61YULNKzFh")

    let signedTransaction = try await client.transaction(digest: digest)
    print("Signed Transaction: `\(String(describing: signedTransaction))`\n")

    let transactionEffects = try await client.transactionEffects(digest: digest)
    print("Transaction Effects: `\(String(describing: transactionEffects))`\n")

    let transactionDataEffects = try await client.transactionDataEffects(digest: digest)
    print("Transaction Data Effects: `\(String(describing: transactionDataEffects))`\n")
  }
}
