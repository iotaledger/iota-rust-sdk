# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio
import sys


def forward_page(cursor=None):
    return PaginationFilter(
        direction=Direction.FORWARD,
        cursor=cursor,
    )


async def fetch_package_versions(client, package_address):
    versions = []
    cursor = None

    while True:
        page = await client.package_versions(
            package_address,
            pagination_filter=forward_page(cursor),
        )
        versions.extend(page.data)
        if page.page_info.has_next_page:
            cursor = page.page_info.end_cursor
        else:
            break

    versions.sort(key=lambda package: package.version())
    return versions


async def print_object_samples(client, type_tag, is_generic):
    if is_generic:
        print("    sample objects: skipped for generic type")
        return

    objects = await client.objects(
        ObjectFilter(type_tag=type_tag),
        forward_page(),
    )

    if len(objects.data) == 0:
        print("    sample objects: none found")
        return

    print("    sample objects:")
    for obj in objects.data:
        print(f"      - {obj.object_id().to_hex()} (version {obj.version()})")
    if objects.page_info.has_next_page:
        print("      - ...")


async def main():
    if len(sys.argv) <= 1:
        raise SystemExit(f"Usage: python3 {sys.argv[0]} <PACKAGE_ID>")

    package_id = sys.argv[1]
    package_address = Address.from_hex(package_id)
    client = GraphQlClient.new_testnet()

    package = await client.package(package_address)
    if package is None:
        raise Exception("missing package")

    latest_package = await client.package_latest(package_address)
    if latest_package is None:
        raise Exception("missing latest package")

    versions = await fetch_package_versions(client, package_address)
    package_prefix = package.id().to_hex()

    print(f"Requested package id: {package_id}")
    print(f"Resolved package id: {package_prefix}")
    print(f"Resolved version: {package.version()}")
    print(
        f"Latest version: {latest_package.version()} ({latest_package.id().to_hex()})"
    )
    print()

    print("Versions:")
    for version in versions:
        labels = []
        if version.id() == package.id():
            labels.append("requested")
        if version.id() == latest_package.id():
            labels.append("latest")

        line = f"- v{version.version()} -> {version.id().to_hex()}"
        if len(labels) > 0:
            line += f" [{', '.join(labels)}]"
        print(line)
    print()

    print("Dependencies:")
    linkage_table = package.linkage_table()
    if len(linkage_table) == 0:
        print("- none")
    else:
        for original_id, upgrade in sorted(
            linkage_table.items(), key=lambda entry: entry[0].to_hex()
        ):
            print(
                f"- {original_id.to_hex()} -> {upgrade.upgraded_id.to_hex()} @ v{upgrade.upgraded_version}"
            )
    print()

    print("Modules, functions, and types:")
    module_names = sorted(module_id.as_str() for module_id in package.modules().keys())

    for module_name in module_names:
        print(f"Module: {module_name}")

        module = await client.normalized_move_module(
            package_address,
            module_name,
            None,
            forward_page(),
            forward_page(),
            forward_page(),
            forward_page(),
        )
        if module is None:
            print("  metadata: missing")
            print()
            continue

        if module.functions is None or len(module.functions.nodes) == 0:
            print("  functions: none")
        else:
            print("  functions:")
            for function in module.functions.nodes:
                print(f"    - {str(function)}")
            if module.functions.page_info.has_next_page:
                print("    - ...")

        if module.structs is None or len(module.structs.nodes) == 0:
            print("  types: none")
        else:
            print("  types:")
            for struct_ in module.structs.nodes:
                type_tag = f"{package_prefix}::{module_name}::{struct_.name}"
                print(f"    - {type_tag}")
                is_generic = (
                    struct_.type_parameters is not None
                    and len(struct_.type_parameters) > 0
                )
                await print_object_samples(client, type_tag, is_generic)
            if module.structs.page_info.has_next_page:
                print("    - ...")

        print()


if __name__ == "__main__":
    asyncio.run(main())
