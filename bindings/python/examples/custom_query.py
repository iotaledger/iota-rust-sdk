# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio
import json


async def main():
    client = GraphQlClient.new_devnet()

    query_epoch_data_str = """
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
    query_epoch_data = CustomQuery(
        query=query_epoch_data_str,
    )
    res = await client.run_custom_query(query_epoch_data)
    print(res)

    variables = [CustomQueryVariable.EPOCH(1)]
    query_epoch_data_with_variables = CustomQuery(
        query=query_epoch_data_str, variables=variables
    )
    res = await client.run_custom_query(query_epoch_data_with_variables)
    print(res)

    query_chain_id_str = """
    query CustomQuery {
        chainIdentifier
    }
    """
    query_chain_id = CustomQuery(
        query=query_chain_id_str,
    )
    res = await client.run_custom_query(query_chain_id)
    print(res)


if __name__ == "__main__":
    asyncio.run(main())
