// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct OwnedObjectsExample {
  static func main() async throws {
    let client = try GraphQlClient.newTestnet()
    let address = Address.zero()
    let objectsPage = try await client.objects(filter: GraphQlObjectFilter(owner: address))
    print("Owned objects(\(objectsPage.data.count)):")
    for obj in objectsPage.data {
      print(obj.id())
    }
  }
}
