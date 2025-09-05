# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *
import asyncio

async def main():
    client = GraphQlClient.new_devnet()
    address = "0x0" # Example address, replace as needed
    address = Address.from_hex(address)
    objects_page = await client.objects(
        PaginationFilter(direction=Direction.FORWARD),
        ObjectFilter(owner=address)
    )
    print(f"Owned objects({len(objects_page.data)}):")
    for obj in objects_page.data:
        print(obj.object_id().to_hex())

if __name__ == "__main__":
    asyncio.run(main())
