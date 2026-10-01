# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()
    address = Address.zero()
    objects_page = await client.objects(GraphQlObjectFilter(owner=address))
    print(f"Owned objects({len(objects_page.data)}):")
    for obj in objects_page.data:
        print(obj.id())


if __name__ == "__main__":
    asyncio.run(main())
