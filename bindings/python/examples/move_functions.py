# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    package_address = Address.from_hex(
        "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d")

    package = await client.package(package_address)
    if package is None:
        raise Exception("missing package")

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
