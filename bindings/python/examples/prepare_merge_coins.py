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
    if len(coins.data) < 2:
        raise Exception("sender needs at least 2 coins to merge")
    coin_0 = PtbArgument.object_id(coins.data[0].id())
    coin_1 = PtbArgument.object_id(coins.data[1].id())

    builder = TransactionBuilder(sender).with_client(client)

    builder.merge_coins(coin_0, [coin_1])

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_tx(txn, False)
    if res.error is not None:
        raise Exception("Failed to merge coins:", res.error)

    print("Merge coins dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
