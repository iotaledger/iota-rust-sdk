// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Fetch all transactions for an address (outgoing and incoming).
//
// The GraphQL service does not have a single filter that returns transactions
// in both directions for an address. To get the full history, run two queries
// and merge the results:
//   * signAddress -> transactions sent by the address (outgoing,
//                    equivalent to GraphQL's `relation: SENT`).
//   * recvAddress -> transactions that transferred objects to the address
//                    (incoming, equivalent to GraphQL's `relation: RECV`).
//
// Omitting both filters effectively returns sent-only, so an address that has
// only ever received coins will appear to have no history unless recvAddress
// is set.

import IotaSDK

@main
struct AddressTransactionsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()
    let address = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    let outgoing = try await client.transactions(
      filter: TransactionsFilter(signAddress: address))
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
