// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct TransactionsWithSharedExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    // The IOTA system state object (0x5) is a well-known shared object that is
    // present on every network including localnet.
    let sharedObjId = try ObjectId.fromHex(hex: "0x5")

    let transactions = try await client.transactions(
      filter: TransactionsFilter(inputObject: sharedObjId))

    for transaction in transactions.data {
      print("Digest:", transaction.transaction.digest().toBase58())
    }
  }
}
