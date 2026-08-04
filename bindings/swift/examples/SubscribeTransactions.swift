// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Tail transactions as they are executed, over a GraphQL subscription.
//
// Unlike the paginated queries, a subscription never ends on its own: it is
// pulled one update at a time and stopped with `cancel`. Localnet may be idle,
// so the example asks the faucet for coins to generate a transaction, and
// cancels after a deadline so it cannot hang.

import Foundation
import IotaSDK

@main
struct SubscribeTransactionsExample {
  static let deadlineNanos: UInt64 = 60_000_000_000

  static func main() async {
    do {
      let client = GraphQlClient.newLocalnet()
      let subscription = await client.transactionsSubscription()

      let activity = Task {
        // Give the subscription a moment to connect before generating activity,
        // otherwise the transaction lands before anyone is listening.
        try await Task.sleep(nanoseconds: 2_000_000_000)
        let address = try Address.fromHex(
          hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
        _ = try await FaucetClient.newLocalnet().requestAndWait(address: address)
      }
      // Cancelling unblocks a pending `next`, which is what keeps the example
      // from waiting forever on a network that produces nothing.
      let watchdog = Task {
        try await Task.sleep(nanoseconds: deadlineNanos)
        subscription.cancel()
      }

      print("Waiting for a transaction...")
      while true {
        guard let update = try await subscription.next() else {
          print("No transaction observed within \(deadlineNanos / 1_000_000_000)s")
          exit(1)
        }

        switch update {
        case .transaction(let transaction):
          let data = transaction.transaction
          print("Digest: \(data.digest().toBase58())")
          print("Sender: \(data.sender().toHex())")
          watchdog.cancel()
          activity.cancel()
          subscription.cancel()
          return
        // Delivery recovers on its own; items in the gap may be missed.
        case .interrupted(let message):
          print("Interrupted: \(message)")
        }
      }
    } catch {
      print("Error: \(error)")
      exit(1)
    }
  }
}
