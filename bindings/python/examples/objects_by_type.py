# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    coins = await client.objects(filter=ObjectFilter(
        type_tag="0x2::coin::Coin<0x2::iota::IOTA>"))

    if len(coins.data) == 0:
        print("No IOTA coin objects found")
    else:
        print("IOTA coin object IDs:")
        for coin in coins.data:
            print(coin.id().to_hex())


if __name__ == "__main__":
    asyncio.run(main())
