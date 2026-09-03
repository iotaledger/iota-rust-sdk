# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    shared_obj_id = ObjectId.from_hex(
        "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")

    transactions = await client.transactions(
        TransactionsFilter().with_input_object(shared_obj_id),)

    for transaction in transactions.data:
        print("Digest:", transaction.transaction.digest().to_base58())


if __name__ == "__main__":
    asyncio.run(main())
