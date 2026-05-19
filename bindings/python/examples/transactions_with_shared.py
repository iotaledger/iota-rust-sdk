# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    # The IOTA system state object (0x5) is a well-known shared object that is
    # present on every network including localnet.
    shared_obj_id = ObjectId.system_state()

    transactions = await client.transactions(
        TransactionsFilter(input_object=shared_obj_id),)

    for transaction in transactions.data:
        print("Digest:", transaction.transaction.digest().to_base58())


if __name__ == "__main__":
    asyncio.run(main())
