// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct TransactionsWithFunctionExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()
    let transactions = try await client.transactions(
      filter: TransactionsFilter().withFunction(function: "0x3::iota_system::request_add_stake"))
    for transaction in transactions.data {
      print("Digest:", transaction.transaction.digest().toBase58())
    }
  }
}
