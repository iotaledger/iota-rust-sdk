// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct TransactionsWithSharedExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let sharedObjId = try ObjectId.fromHex(
      hex: "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")

    let transactions = try await client.transactions(
      filter: TransactionsFilter(inputObject: sharedObjId))

    for transaction in transactions.data {
      print("Digest:", transaction.transaction.digest().toBase58())
    }
  }
}
