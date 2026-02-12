# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    recipient_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    signer_1 = Ed25519PrivateKey(b"\x00" * 32)
    signer_2 = Ed25519PrivateKey(b"\x01" * 32)

    simple_1 = SimpleKeypair.from_ed25519(signer_1)
    simple_2 = SimpleKeypair.from_ed25519(signer_2)

    committee = MultisigCommittee([
        MultisigMember(simple_1.public_key(), 1),
        MultisigMember(simple_2.public_key(), 1),
    ], 2)

    if not committee.is_valid():
        raise Exception("Multisig committee is invalid")

    multisig_address = committee.derive_address()
    print(f"Multisig sender address: {multisig_address.to_hex()}")

    client = GraphQlClient.new_localnet()

    faucet = FaucetClient.new_localnet()
    await faucet.request_and_wait_for_finalized(multisig_address, client)

    builder = TransactionBuilder(multisig_address).with_client(client)
    builder.send_iota(recipient_address, PtbArgument.u64(1000))
    txn = await builder.finish()

    dry_run_result = await client.dry_run_tx(txn)
    if dry_run_result.error is not None:
        raise Exception(f"Dry run failed: {dry_run_result.error}")

    sig_1 = simple_1.sign_transaction(txn)
    sig_2 = simple_2.sign_transaction(txn)

    aggregator = MultisigAggregator.new_with_transaction(committee, txn)
    aggregator = aggregator.with_signature(sig_1)
    aggregator = aggregator.with_signature(sig_2)

    multisig_signature = UserSignature.new_multisig(aggregator.finish())
    effects = await client.execute_tx([multisig_signature], txn)

    print(f"Digest: {hex_encode(effects.digest().to_bytes())}")
    print(f"Transaction status: {effects.as_v1().status}")
    print(f"Effects: {effects.as_v1()}")


if __name__ == "__main__":
    asyncio.run(main())
