# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()
    digest = TransactionDigest.from_base58(
        "3wN9oLKfvCjCd7uFW1D6fp1uSEsD3wJ2cU61YULNKzFh")

    signed_transaction = await client.transaction(digest)
    print(f"Signed Transaction: `{signed_transaction}`\n")

    transaction_effects = await client.transaction_effects(digest)
    print(f"Transaction Effects: `{transaction_effects}`\n")

    transaction_data_effects = await client.transaction_data_effects(digest)
    print(f"Transaction Data Effects: `{transaction_data_effects}`\n")


if __name__ == "__main__":
    asyncio.run(main())
