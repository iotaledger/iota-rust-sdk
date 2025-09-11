# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    object_id = ObjectId.from_hex(
        "0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e"
    )

    obj = await client.object(object_id)
    if obj is None:
        raise Exception("missing object")

    print("Object ID:", obj.object_id().to_hex())
    print("Version:", obj.version())
    print("Previous transaction:", obj.previous_transaction().to_base58())
    print("Owner:", obj.owner())
    print("Storage rebate:", obj.storage_rebate())
    print("Type:", obj.object_type())
    print("BCS bytes:", hex_encode(obj.as_struct().contents))


if __name__ == "__main__":
    asyncio.run(main())
