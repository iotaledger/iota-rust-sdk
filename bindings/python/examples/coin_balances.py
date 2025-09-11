# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    address = Address.from_hex(
        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
    )

    coins = await client.coins(address)
    for coin in coins.data:
        print(f"Coin = {coin.id().to_hex()} Balance = {coin.balance()}")

    balance = await client.balance(address)
    print(f"Total Balance = {balance}")


if __name__ == "__main__":
    asyncio.run(main())
