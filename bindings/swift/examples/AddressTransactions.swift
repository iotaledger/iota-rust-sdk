// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Fetch all transactions for an address (outgoing and incoming).
//
// The GraphQL service does not have a single filter that returns transactions
// in both directions for an address. To get the full history, run two queries
// and merge the results.

import IotaSDK

@main
struct AddressTransactionsExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()
    let address = try Address.fromHex(
      hex: "0xa7c2cf9d8f8d95ff69d7a598c49c77acc36253f496f064a533ad306879b40bfa")

    let outgoing = try await client.transactions(
      filter: TransactionsFilter(sentAddress: address))
    let incoming = try await client.transactions(
      filter: TransactionsFilter(recvAddress: address))

    print("Transactions for \(address.toHex())")

    print("\nOutgoing (sent by address): \(outgoing.data.count)")
    for tx in outgoing.data {
      print("  - \(tx.transaction.digest().toBase58())")
    }

    print("\nIncoming (received by address): \(incoming.data.count)")
    for tx in incoming.data {
      print("  - \(tx.transaction.digest().toBase58())")
    }
  }
}
