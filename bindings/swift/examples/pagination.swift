// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct PaginationExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()
    let address = try Address.fromHex(
      hex: "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

    var allObjects: [Object] = []
    var nextCursor: String? = nil
    while true {
      print("Fetching page with cursor: \(nextCursor ?? "nil")")
      let page = try await client.objects(
        filter: ObjectFilter(owner: address),
        // Limit to 1 to demonstrate pagination
        paginationFilter: PaginationFilter(
          direction: Direction.forward,
          cursor: nextCursor,
          limit: 1)
      )
      allObjects.append(contentsOf: page.data)
      if page.pageInfo.hasNextPage {
        nextCursor = page.pageInfo.endCursor
      } else {
        break
      }
    }
    print("\(allObjects.count) objects fetched:")
    for obj in allObjects {
      print(obj.objectId().toHex())
    }
  }
}
