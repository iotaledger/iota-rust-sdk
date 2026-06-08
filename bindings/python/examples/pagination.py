# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()
    address = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    all_objects = []
    next_cursor = None
    while True:
        print(f"Fetching page with cursor: {next_cursor}")
        page = await client.objects(
            ObjectFilter(owner=address),
            # Limit to 1 to demonstrate pagination
            PaginationFilter(direction=Direction.FORWARD,
                             cursor=next_cursor,
                             limit=1),
        )
        all_objects.extend(page.data)
        if page.page_info.has_next_page:
            next_cursor = page.page_info.end_cursor
        else:
            break
    print(f"{len(all_objects)} objects fetched:")
    for obj_id in all_objects:
        print(obj_id.id().to_hex())


if __name__ == "__main__":
    asyncio.run(main())
