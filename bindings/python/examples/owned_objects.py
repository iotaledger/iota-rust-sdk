# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *
import asyncio


async def main():
    client = GraphQlClient.new_devnet()
    address = Address.from_hex("0x0")
    objects_page = await client.objects(ObjectFilter(owner=address))
    print(f"Owned objects({len(objects_page.data)}):")
    for obj in objects_page.data:
        print(obj.object_id().to_hex())


if __name__ == "__main__":
    asyncio.run(main())
