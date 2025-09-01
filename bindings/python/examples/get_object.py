# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio
import json


async def main():
    client = GraphQlClient.new_devnet()

    object_id = ObjectId.from_hex(
        "0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e"
    )

    obj = await client.move_object_contents(object_id)

    obj_json = json.loads(obj or "")

    print("Domain:", obj_json["domain_name"])


if __name__ == "__main__":
    asyncio.run(main())
