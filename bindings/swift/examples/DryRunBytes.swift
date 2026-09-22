// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct DryRunBytesExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let txBytesBase64 =
      "AAABACAAAKSYS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAEBAQABAADaGCDt9pPuMrVymQe5suyOZJgO6MAIwX6Jz7Tl7NchUQHclW3om5FOan+9g8rr78jskb4SB2Z+pVdjhjkaqCRJzPC6fSAAAAAAILFkUl8sWJyphiT+5+p5Rev6nLCp6DDtMQTNwLSMcOHw2hgg7faT7jK1cpkHubLsjmSYDujACMF+ic+05ezXIVHoAwAAAAAAAICEHgAAAAAAAA=="
    let transaction = try Transaction.fromBase64(base64: txBytesBase64)

    let res = try await client.dryRunTransaction(transaction: transaction)
    if res.error != nil {
      throw NSError(
        domain: "DryRunBytes", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: \(res.error!)"])
    }

    print("Dry run was successful!")
    print("Dry run result: \(res)")
  }
}
