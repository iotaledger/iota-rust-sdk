# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# Fetch all transactions for an address (outgoing and incoming).
#
# The GraphQL service does not have a single filter that returns transactions
# in both directions for an address. To get the full history, run two queries
# and merge the results:
#   * sign_address -> transactions sent by the address (outgoing,
#                     equivalent to GraphQL's `relation: SENT`).
#   * recv_address -> transactions that transferred objects to the address
#                     (incoming, equivalent to GraphQL's `relation: RECV`).
#
# Omitting both filters effectively returns sent-only, so an address that has
# only ever received coins will appear to have no history unless recv_address
# is set.

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()
    address = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    outgoing = await client.transactions(
        TransactionsFilter(sign_address=address))
    incoming = await client.transactions(
        TransactionsFilter(recv_address=address))

    print(f"Transactions for {address.to_hex()}")

    print(f"\nOutgoing (sent by address): {len(outgoing.data)}")
    for tx in outgoing.data:
        print(f"  - {tx.transaction.digest().to_base58()}")

    print(f"\nIncoming (received by address): {len(incoming.data)}")
    for tx in incoming.data:
        print(f"  - {tx.transaction.digest().to_base58()}")


if __name__ == "__main__":
    asyncio.run(main())
