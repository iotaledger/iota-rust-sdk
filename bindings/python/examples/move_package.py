# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


PACKAGE_ADDRESS = "0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f"


async def main():
    client = GraphQlClient.new_devnet()
    package_address = Address.from_hex(PACKAGE_ADDRESS)

    package = await client.package(package_address)
    if package is None:
        raise Exception(f"Missing package: {PACKAGE_ADDRESS}")

    package_id = package.id().to_hex()
    package_version = package.version()

    print(f"Package ID: {package_id}")
    print(f"Current version: {package_version}")
    print()

    versions_page = await client.package_versions(package_address)
    versions = sorted(versions_page.data, key=lambda p: p.version())

    print("Package versions:")
    for versioned_package in versions:
        marker = ""
        if (
            versioned_package.id().to_hex() == package_id
            and versioned_package.version() == package_version
        ):
            marker = " (current)"
        print(
            f"- id={versioned_package.id().to_hex()} "
            f"version={versioned_package.version()}{marker}"
        )
    print()

    print("Dependencies:")
    dependencies = package.linkage_table()
    if len(dependencies) == 0:
        print("- none")
    else:
        for original_id, info in dependencies.items():
            print(
                f"- {original_id.to_hex()} -> {info.upgraded_id.to_hex()} "
                f"(version {info.upgraded_version})"
            )
    print()

    module_ids = sorted(package.modules().keys(), key=lambda module_id: module_id.as_str())
    for module_id in module_ids:
        module_name = module_id.as_str()
        module = await client.normalized_move_module(
            package_address,
            module_name,
            version=package_version,
        )

        if module is None:
            print(f"Module: {module_name} (not found)")
            continue

        print(f"Module: {module_name}")
        print("Functions:")
        if module.functions is None or len(module.functions.nodes) == 0:
            print("- none")
        else:
            for fun in module.functions.nodes:
                print(f"- {str(fun)}")

        print("Types (with sample object if available):")
        if module.structs is None or len(module.structs.nodes) == 0:
            print("- none")
        else:
            for struct in module.structs.nodes:
                type_tag = f"{package_id}::{module_name}::{struct.name}"
                sample_objects = await client.objects(
                    filter=ObjectFilter(type_tag=type_tag),
                    pagination_filter=PaginationFilter(limit=1),
                )
                if len(sample_objects.data) > 0:
                    print(
                        f"- {struct.name} "
                        f"(example object: {sample_objects.data[0].object_id().to_hex()})"
                    )
                else:
                    print(f"- {struct.name} (no example object found)")

        print()


if __name__ == "__main__":
    asyncio.run(main())
