# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()
    parent_object_id = Address.from_hex(
        "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")
    page = await client.dynamic_fields(parent_object_id)
    print("Page size:", len(page.data))
    if page.data:
        print("First field name:\n", page.data[0].name)
        print("First field value:\n", page.data[0].value_as_json)


if __name__ == "__main__":
    asyncio.run(main())
