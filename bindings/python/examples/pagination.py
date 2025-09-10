# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import asyncio
from lib.iota_sdk_ffi import Address, Direction, GraphQlClient, ObjectFilter, PaginationFilter

async def main():
    client = GraphQlClient.new_devnet()
    address = Address.from_hex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

    all_objects = []
    next_cursor = None
    while True:
        print(f"Fetching page with cursor: {next_cursor}")
        page = await client.objects(
            ObjectFilter(owner=address),
            # Limit to 1 to demonstrate pagination
            PaginationFilter(direction=Direction.FORWARD, cursor=next_cursor, limit=1)
        )
        all_objects.extend(page.data)
        if page.page_info.has_next_page:
            next_cursor = page.page_info.end_cursor
        else:
            break
    print(f"{len(all_objects)} objects fetched:")
    for obj_id in all_objects:
        print(obj_id.object_id().to_hex())

if __name__ == "__main__":
    asyncio.run(main())
