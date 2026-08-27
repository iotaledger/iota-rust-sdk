# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    # Amount to send in nanos
    amount = 1000
    recipient_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    private_key = Ed25519PrivateKey(b"\x00" * 32)
    public_key = private_key.public_key()
    sender_address = public_key.derive_address()
    print(f"Sender address: {sender_address.to_hex()}")

    client = GraphQlClient.new_localnet()

    # Request funds from faucet
    faucet = FaucetClient.new_localnet()
    await faucet.request_and_wait_for_finalized(sender_address, client)

    builder = client.transaction_builder(sender_address)
    builder.send_iota(recipient_address, PtbArgument.u64(amount))
    txn = await builder.finish()

    dry_run_result = await client.dry_run_tx(txn)
    if dry_run_result.error is not None:
        raise Exception(f"Dry run failed: {dry_run_result.error}")

    signature = private_key.try_sign_simple(txn.signing_digest())
    user_signature = UserSignature.new_simple(signature)

    effects = await client.execute_tx([user_signature], txn)

    print(f"Digest: {hex_encode(effects.digest().to_bytes())}")
    print(f"Transaction status: {effects.as_v1().status()}")
    print(f"Effects: {effects.as_v1()}")


if __name__ == "__main__":
    asyncio.run(main())
