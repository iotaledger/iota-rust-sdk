# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    from_address = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    to_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        from_address, client)

    coins = await client.coins(from_address)
    if len(coins.data) < 3:
        raise Exception(
            "sender does not own at least 3 coin objects to transfer")
    objs_to_transfer = [
        PtbArgument.object_id(coins.data[0].id()),
        PtbArgument.object_id(coins.data[1].id()),
        PtbArgument.object_id(coins.data[2].id()),
    ]

    builder = TransactionBuilder(from_address).with_client(client)
    builder.transfer_objects(
        to_address,
        objs_to_transfer,
    )

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_tx(txn, False)
    if res.error is not None:
        raise Exception("Failed to transfer objects:", res.error)

    print("Transfer objects dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
