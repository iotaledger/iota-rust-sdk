# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()
    transactions = await client.transactions(
        GraphQlTransactionsFilter().with_function(
            "0x3::iota_system::request_add_stake"),)
    for transaction in transactions.data:
        print("Digest:", transaction.transaction.digest())


if __name__ == "__main__":
    asyncio.run(main())
