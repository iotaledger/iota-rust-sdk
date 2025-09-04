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
        return

    objType = (
        "Package"
        if obj.object_type().is_package()
        else str(obj.object_type().as_struct())
    )

    if obj.owner().is_address():
        objOwner = f"Address({obj.owner().as_address().to_hex()})"
    elif obj.owner().is_object():
        objOwner = f"Object({obj.owner().as_object().to_hex()})"
    elif obj.owner().is_shared():
        objOwner = f"Shared({obj.owner().as_shared()})"
    else:
        objOwner = "Immutable"

    print("Object ID:", obj.object_id().to_hex())
    print("Version:", obj.version())
    print("Previous transaction:", obj.previous_transaction().to_base58())
    print("Owner:", objOwner)
    print("Storage rebate:", obj.storage_rebate())
    print("Type:", objType)
    print("BCS bytes:", obj.as_struct().contents.hex())


if __name__ == "__main__":
    asyncio.run(main())
