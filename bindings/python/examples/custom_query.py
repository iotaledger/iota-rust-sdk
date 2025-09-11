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

    query = CustomQuery(
        query=query,
        variables=json.dumps(variables),
    )

    res = await client.run_custom_query(query)

    print(res)

if __name__ == "__main__":
    asyncio.run(main())
