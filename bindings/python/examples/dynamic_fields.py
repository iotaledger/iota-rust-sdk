# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *
import asyncio


async def main():
    client = GraphQlClient.new_devnet()
    parent_object_id = Address.from_hex(
        "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
    )
    page = await client.dynamic_fields(parent_object_id)
    print("Page size:", len(page.data))
    if page.data:
        print("First field name:\n", page.data[0].name)
        print("First field value:\n", page.data[0].value_as_json)


if __name__ == "__main__":
    asyncio.run(main())
