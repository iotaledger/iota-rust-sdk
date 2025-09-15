# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    try:
        client = GraphQlClient.new_devnet()
        transactions = await client.transactions(
            TransactionsFilter(function="0x3::iota_system::request_add_stake"),
        )
        for transaction in transactions.data:
            print("Digest:", transaction.transaction.digest().to_base58())
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
