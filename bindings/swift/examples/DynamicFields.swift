// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct DynamicFieldsExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()
    // The IOTA system state object owns the validator set and other dynamic
    // fields. It is available on every network including localnet.
    let parentObjectId = try Address.fromHex(hex: "0x5")
    let page = try await client.dynamicFields(address: parentObjectId)
    print("Page size:", page.data.count)
    if let first = page.data.first {
      print("First field name:\n\(first.name)")

      // The field value can be large (e.g. the validator set on 0x5), so we
      // print only the first few lines as a preview.
      let valueString = first.valueAsJson ?? "<none>"
      let previewLines = 15
      let lines = valueString.split(separator: "\n", omittingEmptySubsequences: false)
      let preview = lines.prefix(previewLines).joined(separator: "\n")
      print("First field value (first \(previewLines) lines):")
      print(preview)
      if lines.count > previewLines {
        print("... [truncated]")
      }
    }
  }
}
