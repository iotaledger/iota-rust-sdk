# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GrpcClient.new_testnet()

    object_id = ObjectId.from_hex(
        "0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")

    # `objects` is batched: it takes a list of ids and returns one result per
    # id, in the same order, carrying either the object or the error for that
    # id. The default read mask returns the reference and the BCS-decoded
    # object; pass `read_mask=[GrpcObjectField.REFERENCE()]` to skip the object.
    result = (await client.objects([object_id]))[0]
    if result.error is not None:
        raise RuntimeError(f"Failed to get object: {result.error}")
    obj = result.object.object if result.object is not None else None
    assert obj is not None, "Object not included in the response"

    print("Object ID:", obj.id())
    print("Version:", obj.version())
    print("Previous transaction:", obj.previous_transaction())
    print("Owner:", obj.owner())
    print("Storage rebate:", obj.storage_rebate())
    print("Type:", obj.object_type())
    print("BCS bytes:", hex_encode(obj.as_struct().contents))


if __name__ == "__main__":
    asyncio.run(main())
