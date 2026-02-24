// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct PackageEventsExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let events = try await client.events(
      filter: EventFilter(
        eventType:
          "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba::registry::NameRecordAddedEvent"
      ),
      paginationFilter: PaginationFilter(direction: Direction.forward, limit: 10)
    )

    for event in events.data {
      print("Type: \(event.type)")
      print("Sender: \(event.sender.toHex())")
      print("Module: \(event.module)")
      print("JSON: \(event.json)")
    }
  }
}
