// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GrpcStreamCheckpointsExample {
  static func main() async throws {
    let client = try GrpcClient.newTestnet()

    // Pick a small range of recent checkpoints to stream.
    let latest = try await client.getCheckpointLatest()
    let start = latest.sequenceNumber - 4

    let stream = try await client.streamCheckpoints(
      startSequenceNumber: start, endSequenceNumber: latest.sequenceNumber)

    while let checkpoint = try await stream.next() {
      guard let summary = checkpoint.summary else { continue }
      print(
        "Checkpoint \(checkpoint.sequenceNumber):",
        "epoch \(summary.epoch()),",
        "\(summary.networkTotalTransactions()) total transactions,",
        "timestamp \(summary.timestampMs())")
    }
  }
}
