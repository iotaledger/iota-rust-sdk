# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio
import base64
import json


async def main():
    client = GraphQlClient.new_localnet()
    faucet_client = FaucetClient.new_localnet()

    recipient = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
    )
    amount = 1_000

    # Demo keys. Do not use hardcoded keys like this in production.
    key_1 = Ed25519PrivateKey(bytes([1] * 32))
    key_2 = Ed25519PrivateKey(bytes([2] * 32))

    pk1_b64 = base64.b64encode(key_1.public_key().to_bytes()).decode("ascii")
    pk2_b64 = base64.b64encode(key_2.public_key().to_bytes()).decode("ascii")

    mpk1 = multisig_member_public_key_from_json(
        json.dumps({"scheme": "ed25519", "public_key": pk1_b64})
    )
    mpk2 = multisig_member_public_key_from_json(
        json.dumps({"scheme": "ed25519", "public_key": pk2_b64})
    )

    member_1 = MultisigMember(mpk1, 1)
    member_2 = MultisigMember(mpk2, 1)
    committee = MultisigCommittee([member_1, member_2], 2)
    multisig_address = committee.derive_address()
    print(f"Multisig address: {multisig_address.to_hex()}")

    await faucet_client.request_and_wait_for_finalized(multisig_address, client)

    builder = TransactionBuilder(multisig_address).with_client(client)
    builder.send_iota(recipient, PtbArgument.u64(amount))
    tx = await builder.finish()

    dry_run = await client.dry_run_tx(tx, False)
    if dry_run.error is not None:
        raise Exception(f"Dry run failed: {dry_run.error}")

    sig1 = key_1.sign_transaction(tx)
    sig2 = key_2.sign_transaction(tx)

    aggregator = MultisigAggregator.new_with_transaction(committee, tx)
    aggregator = aggregator.with_signature(sig1)
    aggregator = aggregator.with_signature(sig2)
    agg_sig = aggregator.finish()

    ms_user_sig = UserSignature.new_multisig(agg_sig)
    effects = await client.execute_tx([ms_user_sig], tx, None)
    print(f"Digest: {effects.digest().to_base58()}")


if __name__ == "__main__":
    asyncio.run(main())
