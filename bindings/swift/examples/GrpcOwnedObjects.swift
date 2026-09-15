// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GrpcOwnedObjectsExample {
  static func main() async throws {
    let client = try GrpcClient.newTestnet()

    let owner = try Address.fromHex(
      hex: "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    // First page: 10 results, no filter on type. The returned page includes a
    // `nextPageToken` to feed back in for the following page.
    let page = try await client.ownedObjects(
      owner: owner, objectType: nil, pageSize: 10, pageToken: nil)
    print("First page: \(page.objects.count) objects")
    for obj in page.objects {
      print(" ", obj.objectId!.toHex())
    }
    if page.nextPageToken != nil {
      print("  ...more pages available")
    }

    // Auto-paginate: only IOTA coins, capped at 50 across all pages.
    let coins = try await client.allOwnedObjects(
      owner: owner, objectType: StructTag.newGasCoin(), limit: 50)
    print("---")
    print("Up to 50 IOTA coin objects (\(coins.count) returned):")
    for obj in coins {
      print(" ", obj.objectId!.toHex())
    }
  }
}
