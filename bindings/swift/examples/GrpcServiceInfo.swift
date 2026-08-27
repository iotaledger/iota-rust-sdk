// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct GrpcServiceInfoExample {
  static func main() async throws {
    let client = try GrpcClient.newTestnet()

    let info = try await client.getServiceInfo()
    if let chainId = info.chainId {
      print("Chain ID:", chainId)
    }
    if let epoch = info.epoch {
      print("Epoch:", epoch)
    }
    if let checkpointHeight = info.checkpointHeight {
      print("Checkpoint height:", checkpointHeight)
    }

    let gasPrice = try await client.getReferenceGasPrice()
    print("Reference gas price:", gasPrice)
  }
}
