// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

let howMany: UInt64 = 5

@main
struct GrpcCheckpointsStreamExample {
  static func main() async throws {
    let client = try GrpcClient.newLocalnet()

    // Pick a starting point a few checkpoints behind head so the example
    // returns promptly instead of waiting on new blocks.
    let head = try await client.checkpointLatest().sequenceNumber
    let start = head >= howMany - 1 ? head - (howMany - 1) : 0
    let end = head

    // Only ask for the summary — keeps the message small. Pass nil (or
    // compose more fields) to pull more data per checkpoint.
    let stream = try await client.checkpointsStream(
      startSequenceNumber: start, endSequenceNumber: end, readMask: [.checkpointSummary])

    print("Streaming checkpoints \(start)..=\(end)")
    while let checkpoint = try await stream.next() {
      guard let summary = checkpoint.summary else {
        fatalError("Checkpoint \(checkpoint.sequenceNumber) has no summary")
      }
      print(
        "  cp \(String(checkpoint.sequenceNumber).leftPadded(to: 6))  "
          + "epoch \(String(summary.epoch()).leftPadded(to: 3))  "
          + "txs \(String(summary.networkTotalTransactions()).leftPadded(to: 4))  "
          + "ts \(summary.timestampMs())")
    }
  }
}

extension String {
  fileprivate func leftPadded(to width: Int) -> String {
    String(repeating: " ", count: max(0, width - count)) + self
  }
}
