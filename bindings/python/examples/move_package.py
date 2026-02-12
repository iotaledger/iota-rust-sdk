# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    package_address = Address.from_hex(
        "0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")

    package_versions = await client.package_versions(package_address)
    if len(package_versions.data) == 0:
        raise Exception("No package versions found")

    versions = sorted([pkg.version() for pkg in package_versions.data])
    print(f"Versions: {versions}")

    latest_package = await client.package_latest(package_address)
    if latest_package is None:
        raise Exception("Latest package not found")

    print(f"Latest package id: {latest_package.id().to_hex()}")
    print(f"Latest package version: {latest_package.version()}")

    dependencies = latest_package.linkage_table()
    if len(dependencies) == 0:
        print("Dependencies: none")
    else:
        print("Dependencies:")
        for dep_id in dependencies.keys():
            print(f"- {dep_id.to_hex()}")

    for module_id in latest_package.modules():
        module = await client.normalized_move_module(
            package_address,
            module_id.as_str(),
            latest_package.version(),
        )
        if module is None:
            continue

        print(f"\nModule: {module_id.as_str()}")

        if module.functions is not None:
            print(f"Functions: {len(module.functions.nodes)}")

        if module.structs is not None:
            print(f"Structs: {len(module.structs.nodes)}")
            for move_struct in module.structs.nodes[:2]:
                struct_type = f"{latest_package.id().to_hex()}::{module_id.as_str()}::{move_struct.name}"
                typed_objects = await client.objects(
                    filter=ObjectFilter(type_tag=struct_type))
                if len(typed_objects.data) > 0:
                    print(
                        f"- {move_struct.name} -> example object {typed_objects.data[0].object_id().to_hex()}")
                else:
                    print(f"- {move_struct.name} -> no objects found")


if __name__ == "__main__":
    asyncio.run(main())
