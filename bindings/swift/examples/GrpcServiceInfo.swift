// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GrpcServiceInfoExample {
  static func main() async throws {
    let client = try GrpcClient.newTestnet()

    let info = try await client.serviceInfo()
    if let chainId = info.chainId {
      print("Chain ID:", chainId)
    }
    if let epoch = info.epoch {
      print("Epoch:", epoch)
    }
    if let checkpointHeight = info.executedCheckpointHeight {
      print("Checkpoint height:", checkpointHeight)
    }

    let gasPrice = try await client.referenceGasPrice()
    print("Reference gas price:", gasPrice)
  }
}
