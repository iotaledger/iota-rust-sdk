// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct PackageEventsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let events = try await client.events(
      filter: EventFilter(
        eventType:
          "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent"
      ),
      paginationFilter: PaginationFilter(direction: Direction.forward, limit: 10)
    )

    for event in events.data {
      // Sender and module are optional: some events (such as system- or
      // genesis-emitted ones) carry neither.
      print("Type: \(event.type)")
      print("Sender: \(event.sender?.toHex() ?? "none")")
      print("Module: \(event.module ?? "none")")
      print("JSON: \(event.json)")
    }
  }
}
