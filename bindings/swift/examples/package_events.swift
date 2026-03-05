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
          "0x7aec8176867a0c8d2803d758ebf98226d301ef0f00393879ea718f6bd1554f16::registry::NameRecordAddedEvent"
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
