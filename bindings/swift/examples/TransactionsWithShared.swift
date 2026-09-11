// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct TransactionsWithSharedExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let sharedObjId = try ObjectId.fromHex(
      hex: "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")

    let transactions = try await client.transactions(
      filter: TransactionsFilter().withInputObject(inputObject: sharedObjId))

    for transaction in transactions.data {
      print("Digest:", transaction.transaction.digest().toBase58())
    }
  }
}
