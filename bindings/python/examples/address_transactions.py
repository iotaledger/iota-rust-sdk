# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# Fetch all transactions for an address (outgoing and incoming).
#
# The GraphQL service does not have a single filter that returns transactions
# in both directions for an address. To get the full history, run two queries
# and merge the results.

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()
    address = Address.from_hex(
        "0xa7c2cf9d8f8d95ff69d7a598c49c77acc36253f496f064a533ad306879b40bfa")

    outgoing = await client.transactions(
        TransactionsFilter().with_sent_address(address))
    incoming = await client.transactions(
        TransactionsFilter().with_recv_address(address))

    print(f"Transactions for {address.to_hex()}")

    print(f"\nOutgoing (sent by address): {len(outgoing.data)}")
    for tx in outgoing.data:
        print(f"  - {tx.transaction.digest().to_base58()}")

    print(f"\nIncoming (received by address): {len(incoming.data)}")
    for tx in incoming.data:
        print(f"  - {tx.transaction.digest().to_base58()}")


if __name__ == "__main__":
    asyncio.run(main())
