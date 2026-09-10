# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GrpcClient.new_testnet()

    object_id = ObjectId.from_hex(
        "0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")

    # `objects` is batched: it takes a list of requests and returns the objects
    # in the same order.
    obj = (await client.objects([ObjectRequest(object_id=object_id)]))[0]

    print("Object ID:", obj.id().to_hex())
    print("Version:", obj.version())
    print("Previous transaction:", obj.previous_transaction().to_base58())
    print("Owner:", obj.owner())
    print("Storage rebate:", obj.storage_rebate())
    print("Type:", obj.object_type())
    print("BCS bytes:", hex_encode(obj.as_struct().contents))


if __name__ == "__main__":
    asyncio.run(main())
