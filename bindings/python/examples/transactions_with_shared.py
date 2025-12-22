# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    shared_obj_id = ObjectId.from_hex(
        "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")

    transactions = await client.transactions(
        TransactionsFilter(input_object=shared_obj_id),)

    for transaction in transactions.data:
        print("Digest:", transaction.transaction.digest().to_base58())


if __name__ == "__main__":
    asyncio.run(main())
