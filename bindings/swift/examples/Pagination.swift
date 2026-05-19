// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct PaginationExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()
    let address = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: address, client: client)

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
