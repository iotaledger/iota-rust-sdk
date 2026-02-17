// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct DynamicFieldsExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()
    let parentObjectId = try Address.fromHex(
      hex: "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")
    let page = try await client.dynamicFields(address: parentObjectId)
    print("Page size:", page.data.count)
    if !page.data.isEmpty {
      print("First field name:\n", page.data[0].name)
      print("First field value:\n", page.data[0].valueAsJson)
    }
  }
}
