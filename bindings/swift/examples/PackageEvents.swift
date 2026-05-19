// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct PackageEventsExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    // Query events emitted by the validator-set module in the IOTA system
    // framework (0x3). These fire on every epoch change so they are reliably
    // present on every network including localnet.
    let events = try await client.events(
      filter: EventFilter(
        eventType: "0x3::validator::StakingRequestEvent"
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
