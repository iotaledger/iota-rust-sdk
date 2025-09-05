# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    package_address = Address.from_hex(
        "0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f"
    )

    package = await client.package(package_address)
    if package is None:
        print("no package found")
        return

    for module_id in package.modules():
        module = await client.normalized_move_module(
            package_address,
            module_id.as_str(),
        )
        if module is None:
            print(f"module `{module_id.as_str()}` not found")
            return
        if module.functions is not None:
            print(f"Module: {module_id.as_str()}")
            for fun in module.functions.nodes:
                print(f"- {str(fun)}")
            print()


if __name__ == "__main__":
    asyncio.run(main())
