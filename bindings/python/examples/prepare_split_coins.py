# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    sender = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        sender, client)

    coins = await client.coins(sender)
    if len(coins.data) == 0:
        raise Exception("sender has no coins")
    coin_id = coins.data[0].id()

    builder = TransactionBuilder(sender).with_client(client)

    builder.split_coins(
        PtbArgument.object_id(coin_id),
        [PtbArgument.u64(1000),
         PtbArgument.u64(2000),
         PtbArgument.u64(3000)],
        ["coin1", "coin2", "coin3"],
    ).transfer_objects(
        sender,
        [
            PtbArgument.assigned("coin1"),
            PtbArgument.assigned("coin2"),
            PtbArgument.assigned("coin3"),
        ],
    )

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await builder.dry_run(False)
    if res.error is not None:
        raise Exception("Failed to split coins:", res.error)

    print("Split coins dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
