// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct UnstakeExample {
  static func main() async throws {
    let client = GraphQlClient.newLocalnet()

    let privateKey = try Ed25519PrivateKey(bytes: Data(repeating: 9, count: 32))
    let owner = privateKey.publicKey().deriveAddress()

    let faucet = FaucetClient.newLocalnet()
    _ = try await faucet.requestAndWaitForFinalized(address: owner, client: client)

    let validators = try await client.activeValidators()
    guard let validator = validators.data.first else {
      throw NSError(
        domain: "Unstake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "no validators found"])
    }
    let stakeBuilder = client.transactionBuilder(sender: owner)
    _ = stakeBuilder.stake(
      stake: PtbArgument.u64(value: 1_000_000_000), validatorAddress: validator.address)
    let stakeTx = try await stakeBuilder.finish()
    let signature = try privateKey.signTransaction(transaction: stakeTx)
    _ = try await client.executeTransaction(
      signatures: [signature], transaction: stakeTx, waitFor: WaitForTransaction.finalized)

    let stakedIotas = try await client.objects(
      filter: ObjectFilter(
        typeTag: String(describing: StructTag.newStakedIota()), owner: owner))
    if stakedIotas.data.isEmpty {
      throw NSError(
        domain: "Unstake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "no staked iotas found"])
    }
    let stakedIota = stakedIotas.data[0]

    let builder = client.transactionBuilder(sender: stakedIota.owner().asAddress())

    _ = builder.unstake(stakedIota: PtbArgument.objectId(id: stakedIota.id()))

    let res = try await builder.dryRun()
    if res.error != nil {
      throw NSError(
        domain: "Unstake", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Failed to unstake: \(res.error!)"])
    }

    print("Unstake dry run was successful!")
  }
}
