// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct StakeExample {
  static func main() async throws {
    let client = GraphQlClient.newDevnet()

    let myAddress = try Address.fromHex(
      hex: "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

    let validators = try await client.activeValidators()
    if validators.data.isEmpty {
      throw NSError(
        domain: "Stake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "no validators found"])
    }
    let validator = validators.data[0]

    print("Staking to validator", validator.name ?? "with no name")

    let builder = TransactionBuilder(sender: myAddress).withClient(client: client)

    builder.stake(stake: PtbArgument.u64(value: 1_000_000_000), validatorAddress: validator.address)

    let res = try await builder.dryRun()
    if res.error != nil {
      throw NSError(
        domain: "Stake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to stake: \(res.error!)"])
    }

    print("Stake dry run was successful!")
  }
}
