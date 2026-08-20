# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# 2-of-3 Ed25519 multisig example.
#
# Derives 3 keypairs from a mnemonic at indices 0, 1, 2, creates a multisig
# committee with threshold 2, funds the multisig address via faucet, builds
# a send_iota transaction, signs with only 2 of the 3 keys, aggregates,
# and executes.
#
# Requires a running localnet (`iota start --force-regenesis`).

from lib.iota_sdk import *

import asyncio

MNEMONIC = "round attack kitchen wink winter music trip tiny nephew hire orange what"


async def main():
    amount = 1000
    recipient_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    # 1. Derive 3 Ed25519 keypairs from mnemonic at indices 0, 1, 2
    key0 = Ed25519PrivateKey.from_mnemonic(MNEMONIC, 0)
    key1 = Ed25519PrivateKey.from_mnemonic(MNEMONIC, 1)
    key2 = Ed25519PrivateKey.from_mnemonic(MNEMONIC, 2)

    # 2. Get MultisigMemberPublicKey via SimpleKeypair
    kp0 = SimpleKeypair.from_ed25519(key0)
    kp1 = SimpleKeypair.from_ed25519(key1)
    kp2 = SimpleKeypair.from_ed25519(key2)

    # 3. Build multisig committee: threshold=2, each member weight=1
    committee = MultisigCommittee(
        [
            MultisigMember(kp0.public_key(), 1),
            MultisigMember(kp1.public_key(), 1),
            MultisigMember(kp2.public_key(), 1),
        ],
        2,
    )

    # 4. Derive multisig address
    multisig_address = committee.derive_address()
    print(f"Multisig address: {multisig_address.to_hex()}")

    client = GraphQlClient.new_localnet()

    # 5. Fund the multisig address
    faucet = FaucetClient.new_localnet()
    await faucet.request_and_wait_for_finalized(multisig_address, client)

    # 6. Build a send_iota transaction
    builder = client.transaction_builder(multisig_address)
    builder.send_iota(recipient_address, PtbArgument.u64(amount))
    txn = await builder.finish()

    dry_run_result = await client.dry_run_tx(txn)
    if dry_run_result.error is not None:
        raise Exception(f"Dry run failed: {dry_run_result.error}")

    # 7. Sign with key0 and key1 (2-of-3 threshold)
    sig0 = kp0.sign_transaction(txn)
    sig1 = kp1.sign_transaction(txn)

    # 8. Aggregate signatures
    aggregator = MultisigAggregator.new_with_transaction(committee, txn)
    aggregator = aggregator.with_signature(sig0)
    aggregator = aggregator.with_signature(sig1)
    agg_sig = aggregator.finish()

    # 9. Execute
    user_signature = UserSignature.new_multisig(agg_sig)
    effects = await client.execute_tx([user_signature], txn)

    print(f"Digest: {hex_encode(effects.digest().to_bytes())}")
    print(f"Transaction status: {effects.as_v1().status}")
    print(f"Effects: {effects.as_v1()}")


if __name__ == "__main__":
    asyncio.run(main())
