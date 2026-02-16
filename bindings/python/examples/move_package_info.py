# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

"""
Example: Query Move Package Information

This example demonstrates how to fetch and display comprehensive information
about a Move package, including:
- Package versions
- Modules and their functions
- Dependencies
- Types defined in the package
- Example objects of those types
"""

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    # Example package ID (replace with actual package ID)
    package_id = Address.from_hex(
        "0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")

    print(f"Fetching information for package: {package_id.to_hex()}\n")

    # Fetch the package object
    package = await client.package(package_id)
    if package is None:
        raise Exception(f"Package not found at address: {package_id.to_hex()}")

    # Display package version
    print("=== Package Version ===")
    print(f"Current version: {package.version}")
    print()

    # Display modules and their functions
    print("=== Modules ===")
    for module_id, module in package.modules.items():
        print(f"Module: {module_id}")

        # Fetch detailed module information
        normalized_module = await client.normalized_move_module(
            package_id, module_id
        )

        if normalized_module:
            # Display functions
            if normalized_module.functions:
                print("  Functions:")
                for fun in normalized_module.functions.nodes:
                    print(f"    - {fun.name}")

            # Display structs/types
            if normalized_module.structs:
                print("  Types:")
                for struct_def in normalized_module.structs.nodes:
                    print(f"    - {struct_def.name}")

                    # Try to find example objects of this type
                    try:
                        objects = await client.objects_by_type(
                            f"{package_id.to_hex()}::{module_id}::{struct_def.name}",
                            first=3  # Limit to 3 examples
                        )
                        if objects:
                            print("      Example objects:")
                            for obj in objects:
                                print(f"        - Object ID: {obj.object_id().to_hex()}")
                    except Exception:
                        # Ignore errors when fetching objects
                        pass

        print()

    # Display dependencies (from package's previous transaction)
    if package.previous_transaction:
        print("=== Previous Transaction ===")
        print(f"Transaction digest: {package.previous_transaction.to_base58()}")

    print()
    print("Package information fetched successfully!")


if __name__ == "__main__":
    asyncio.run(main())
