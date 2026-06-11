// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct ObjectsByTypeExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let stakedIotas = try await client.objects(
      filter: ObjectFilter(typeTag: "0x3::staking_pool::StakedIota"))

    if stakedIotas.data.isEmpty {
      print("No StakedIota objects found")
    } else {
      print("StakedIota object IDs:")
      for stakedIota in stakedIotas.data {
        print(stakedIota.id().toHex())
      }
    }
  }
}
