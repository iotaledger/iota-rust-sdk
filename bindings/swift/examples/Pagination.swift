// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct PaginationExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()
    let address = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

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
      print(obj.id().toHex())
    }
  }
}
