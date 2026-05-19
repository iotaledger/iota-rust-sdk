// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct StakeExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let myAddress = try Address.fromHex(
      hex: "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

    _ = try await FaucetClient.newLocalnet().requestAndWaitForFinalized(
      address: myAddress, client: client)

    let validators = try await client.activeValidators()
    if validators.data.isEmpty {
      throw NSError(
        domain: "Stake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "no validators found"])
    }
    let validator = validators.data[0]

    print("Staking to validator", validator.name ?? "with no name")

    let builder = TransactionBuilder(sender: myAddress).withClient(client: client)

    _ = builder.stake(
      stake: PtbArgument.u64(value: 1_000_000_000), validatorAddress: validator.address)

    let res = try await builder.dryRun(skipChecks: false)
    if res.error != nil {
      throw NSError(
        domain: "Stake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to stake: \(res.error!)"])
    }

    print("Stake dry run was successful!")
  }
}
