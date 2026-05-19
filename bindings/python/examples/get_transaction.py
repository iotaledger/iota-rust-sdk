# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    transactions = await client.transactions()
    if len(transactions.data) == 0:
        raise Exception("no transactions available on the network")
    digest = transactions.data[0].transaction.digest()
    print(f"Querying transaction: {digest.to_base58()}")

    signed_transaction = await client.transaction(digest)
    print(f"Signed Transaction: `{signed_transaction}`\n")

    transaction_effects = await client.transaction_effects(digest)
    print(f"Transaction Effects: `{transaction_effects}`\n")

    transaction_data_effects = await client.transaction_data_effects(digest)
    print(f"Transaction Data Effects: `{transaction_data_effects}`\n")


if __name__ == "__main__":
    asyncio.run(main())
