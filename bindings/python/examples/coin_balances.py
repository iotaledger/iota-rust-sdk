# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    address = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    coins = await client.coins(address)
    for coin in coins.data:
        print(
            f"Coin = {coin.id().to_hex()}, Coin Type = {coin.coin_type().as_struct_tag()}, Balance = {coin.balance()}"
        )

    balance = await client.balance(address) or 0
    print(f"Total Balance = {balance}")


if __name__ == "__main__":
    asyncio.run(main())
