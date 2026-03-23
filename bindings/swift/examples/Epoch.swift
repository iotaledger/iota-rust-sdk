// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct EpochExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    // Get current epoch
    guard let currentEpoch = try await client.epoch() else {
      throw NSError(
        domain: "Epoch", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "missing current epoch"])
    }

    print("Current epoch: \(currentEpoch.epochId)")
    print("Current epoch start time: \(currentEpoch.startTimestamp)")

    // Get previous epoch
    let previousEpochId = currentEpoch.epochId - 1
    guard let previousEpoch = try await client.epoch(epoch: previousEpochId) else {
      throw NSError(
        domain: "Epoch", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "missing previous epoch"])
    }

    print("Previous epoch: \(previousEpoch.epochId)")
    if let totalStakeRewards = previousEpoch.totalStakeRewards {
      print("Previous epoch stake rewards: \(totalStakeRewards)")
    }
  }
}
