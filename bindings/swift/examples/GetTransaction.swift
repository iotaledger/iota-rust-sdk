// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GetTransactionExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let latestPage = try await client.transactions()
    guard let latest = latestPage.data.first else {
      throw NSError(
        domain: "GetTransaction", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "no transactions available on the network"])
    }
    let digest = latest.transaction.digest()
    print("Querying transaction: \(digest.toBase58())")

    let signedTransaction = try await client.transaction(digest: digest)
    print("Signed Transaction: `\(String(describing: signedTransaction))`\n")

    let transactionEffects = try await client.transactionEffects(digest: digest)
    print("Transaction Effects: `\(String(describing: transactionEffects))`\n")

    let transactionDataEffects = try await client.transactionDataEffects(digest: digest)
    print("Transaction Data Effects: `\(String(describing: transactionDataEffects))`\n")
  }
}
