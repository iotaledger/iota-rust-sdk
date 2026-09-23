# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio

# The `view_demo` package published on testnet.
PACKAGE = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4"
# A shared `view_demo::shop::Shop` created when the package was published.
SHOP = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20"


async def main():
    client = GraphQlClient.new_testnet()

    # ===========================================================================
    # Example 1: Using move_view_call() with typed arguments (primitives)
    # ===========================================================================
    print(
        "=== Example 1: move_view_call() with typed arguments (primitives) ===")
    print()

    price_args = [MoveViewArg.u64(100), MoveViewArg.u64(25)]

    result = await client.move_view_call(f"{PACKAGE}::shop::discounted_price",
                                         None, price_args)

    if result.error is not None:
        print("Error:", result.error)
    elif result.results is not None:
        print("Results:", result.results)
    else:
        print("No results")

    # ===========================================================================
    # Example 2: Using move_view_call_json() with JSON values (primitives)
    # ===========================================================================
    print()
    print(
        "=== Example 2: move_view_call_json() with JSON values (primitives) ==="
    )
    print()

    # `u64` is passed as a string so large values survive JSON.
    json_result = await client.move_view_call_json(
        f"{PACKAGE}::shop::discounted_price", None, ['"100"', '"25"'])

    if json_result.error is not None:
        print("JSON Error:", json_result.error)
    elif json_result.results is not None:
        print("JSON Results:", json_result.results)
    else:
        print("No JSON results")

    # ===========================================================================
    # Example 3: Using move_view_call() with typed arguments (shared object)
    # ===========================================================================
    print()
    print(
        "=== Example 3: move_view_call() with typed arguments (shared object) ==="
    )
    print()

    shop_args = [
        MoveViewArg.object_id(ObjectId.from_hex(SHOP)),
        MoveViewArg.u64(1)
    ]

    shop_result = await client.move_view_call(f"{PACKAGE}::shop::sale_at", None,
                                              shop_args)

    if shop_result.error is not None:
        print("Shop Error:", shop_result.error)
    elif shop_result.results is not None:
        print("Shop Results:", shop_result.results)
    else:
        print("No shop results")

    # ===========================================================================
    # Example 4: Using move_view_call_json() with JSON values (shared object)
    # ===========================================================================
    print()
    print(
        "=== Example 4: move_view_call_json() with JSON values (shared object) ==="
    )
    print()

    shop_json_result = await client.move_view_call_json(
        f"{PACKAGE}::shop::sale_at", None, [f'"{SHOP}"', '"1"'])

    if shop_json_result.error is not None:
        print("Shop JSON Error:", shop_json_result.error)
    elif shop_json_result.results is not None:
        print("Shop JSON Results:", shop_json_result.results)
    else:
        print("No shop JSON results")

    # ===========================================================================
    # Example 5: Using move_view_call_builder() to assemble the call
    # ===========================================================================
    print()
    print("=== Example 5: move_view_call_builder() ===")
    print()

    builder = client.move_view_call_builder(ObjectId.from_hex(PACKAGE), "shop",
                                            "sale_at")
    builder = builder.arguments(
        [MoveViewArg.object_id(ObjectId.from_hex(SHOP)),
         MoveViewArg.u64(1)])

    print("Builder Results:", await builder.execute())


if __name__ == "__main__":
    asyncio.run(main())
