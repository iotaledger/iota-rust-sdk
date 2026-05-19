# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    address = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        address, client)

    coins = await client.coins(address)
    for coin in coins.data:
        print(
            f"Coin = {coin.id().to_hex()}, Coin Type = {coin.coin_type().as_struct_tag()}, Balance = {coin.balance()}"
        )

    balance = await client.balance(address) or 0
    print(f"Total Balance = {balance}")


if __name__ == "__main__":
    asyncio.run(main())
