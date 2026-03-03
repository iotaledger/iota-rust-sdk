// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct DynamicFieldsExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()
    let parentObjectId = try Address.fromHex(
      hex: "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")
    let page = try await client.dynamicFields(address: parentObjectId)
    print("Page size:", page.data.count)
    if !page.data.isEmpty {
      print("First field name:\n", page.data[0].name)
      print("First field value:\n", page.data[0].valueAsJson as Any)
    }
  }
}
