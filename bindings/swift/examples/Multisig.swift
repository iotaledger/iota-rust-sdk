// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// 2-of-3 Ed25519 multisig example.
//
// Derives 3 keypairs from a mnemonic at indices 0, 1, 2, creates a multisig
// committee with threshold 2, funds the multisig address via faucet, builds
// a send_iota transaction, signs with only 2 of the 3 keys, aggregates,
// and executes.
//
// Requires a running localnet (`iota start --force-regenesis`).

import Foundation
import IotaSDK

let multisigMnemonic = "round attack kitchen wink winter music trip tiny nephew hire orange what"

@main
struct MultisigExample {
  static func main() async throws {
    let amount: UInt64 = 1000
    let recipientAddress = try Address.fromHex(
      hex: "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    // 1. Derive 3 Ed25519 keypairs from mnemonic at indices 0, 1, 2
    let key0 = try Ed25519PrivateKey.fromMnemonic(phrase: multisigMnemonic, accountIndex: 0)
    let key1 = try Ed25519PrivateKey.fromMnemonic(phrase: multisigMnemonic, accountIndex: 1)
    let key2 = try Ed25519PrivateKey.fromMnemonic(phrase: multisigMnemonic, accountIndex: 2)

    // 2. Get MultisigMemberPublicKey via SimpleKeypair
    let kp0 = SimpleKeypair.fromEd25519(keypair: key0)
    let kp1 = SimpleKeypair.fromEd25519(keypair: key1)
    let kp2 = SimpleKeypair.fromEd25519(keypair: key2)

    // 3. Build multisig committee: threshold=2, each member weight=1
    let committee = try MultisigCommittee(
      members: [
        MultisigMember(publicKey: kp0.publicKey(), weight: 1),
        MultisigMember(publicKey: kp1.publicKey(), weight: 1),
        MultisigMember(publicKey: kp2.publicKey(), weight: 1),
      ],
      threshold: 2
    )

    // 4. Derive multisig address
    let multisigAddress = committee.deriveAddress()
    print("Multisig address: \(multisigAddress.toHex())")

    let client = GraphQlClient.newLocalnet()

    // 5. Fund the multisig address
    let faucet = FaucetClient.newLocalnet()
    _ = try await faucet.requestAndWaitForFinalized(address: multisigAddress, client: client)

    // 6. Build a send_iota transaction
    let builder = client.transactionBuilder(sender: multisigAddress)
    _ = builder.sendIota(recipient: recipientAddress, amount: PtbArgument.u64(value: amount))
    let txn = try await builder.finish()

    let dryRunResult = try await client.dryRunTransaction(transaction: txn)
    if dryRunResult.error != nil {
      throw NSError(
        domain: "Multisig", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Dry run failed: \(dryRunResult.error!)"])
    }

    // 7. Sign with key0 and key1 (2-of-3 threshold)
    let sig0 = try kp0.signTransaction(transaction: txn)
    let sig1 = try kp1.signTransaction(transaction: txn)

    // 8. Aggregate signatures
    let aggregator = MultisigAggregator.newWithTransaction(committee: committee, transaction: txn)
    try aggregator.addSignature(signature: sig0)
    try aggregator.addSignature(signature: sig1)
    let aggSig = try aggregator.finish()

    // 9. Execute
    let userSignature = UserSignature.newMultisig(signature: aggSig)
    let effects = try await client.executeTransaction(signatures: [userSignature], transaction: txn)

    print("Digest: \(hexEncode(input: effects.digest().toBytes()))")
    print("Transaction status: \(effects.asV1().status())")
    print("Effects: \(effects.asV1())")
  }
}
