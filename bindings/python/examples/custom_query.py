# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio
import json


async def main():
    client = GraphQlClient.new_devnet()

    query = """
    query CustomQuery($id: UInt53) {
        epoch(id: $id) {
            epochId
            referenceGasPrice
            totalGasFees
            totalCheckpoints
            totalTransactions
        }
    }
    """
    variables = {"id": 1}

    payload1 = CustomQuery(
        query=query,
        variables=json.dumps(variables),
    )
    res = await client.run_custom_query(payload1)
    print(res)

    payload2 = CustomQuery(
        query=query,
        variables=None,
    )
    res = await client.run_custom_query(payload2)
    print(res)


if __name__ == "__main__":
    asyncio.run(main())
