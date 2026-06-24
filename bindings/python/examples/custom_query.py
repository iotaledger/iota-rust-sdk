# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio
import json


async def main():
    client = GraphQlClient.new_testnet()

    query_epoch_data_str = """
    query MyQuery($id: UInt53) {
        epoch(id: $id) {
            epochId
            referenceGasPrice
            totalGasFees
            totalCheckpoints
            totalTransactions
        }
    }
    """
    query_epoch_data = Query(query_text=query_epoch_data_str,)
    res = await client.run_query(query_epoch_data)
    print(res)

    variables = {"id": 1}
    query_epoch_data_with_variables = Query(query_text=query_epoch_data_str,
                                            variables=json.dumps(variables))
    res = await client.run_query(query_epoch_data_with_variables)
    print(res)

    query_chain_id_str = """
    query MyQuery {
        chainIdentifier
    }
    """
    query_chain_id = Query(query_text=query_chain_id_str,)
    res = await client.run_query(query_chain_id)
    print(res)


if __name__ == "__main__":
    asyncio.run(main())
