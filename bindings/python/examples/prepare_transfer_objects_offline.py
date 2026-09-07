# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    private_key = Ed25519PrivateKey(b"\x09" * 32)
    from_address = private_key.public_key().derive_address()
    to_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    faucet = FaucetClient.new_localnet()
    await faucet.request_and_wait_for_finalized(from_address, client)

    coins = (await client.objects(ObjectFilter(owner=from_address))).data
    gas_coin = coins[0]
    objs_to_transfer = [
        PtbArgument.object_ref(coin.object_ref()) for coin in coins[1:]
    ]
    gas_price = await client.reference_gas_price() or 100

    builder = TransactionBuilder(from_address)
    builder.transfer_objects(
        to_address,
        objs_to_transfer,
    )
    builder.gas([gas_coin.object_ref()
                ]).gas_price(gas_price).gas_budget(500000000)

    txn = builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_transaction(txn)
    if res.error is not None:
        raise Exception("Failed to transfer objects:", res.error)

    print("Transfer objects dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
