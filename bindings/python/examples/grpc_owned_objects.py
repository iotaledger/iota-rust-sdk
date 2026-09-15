# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GrpcClient.new_testnet()

    owner = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    # First page: 10 results, no filter on type. The returned page includes a
    # `next_page_token` to feed back in for the following page.
    page = await client.owned_objects(owner, None, 10)
    print(f"First page: {len(page.objects)} objects")
    for obj in page.objects:
        print(" ", obj.object_id.to_hex())
    if page.next_page_token is not None:
        print("  ...more pages available")

    # Auto-paginate: only IOTA coins, capped at 50 across all pages.
    coins = await client.all_owned_objects(owner, StructTag.new_gas_coin(), 50)
    print("---")
    print(f"Up to 50 IOTA coin objects ({len(coins)} returned):")
    for obj in coins:
        print(" ", obj.object_id.to_hex())


if __name__ == "__main__":
    asyncio.run(main())
