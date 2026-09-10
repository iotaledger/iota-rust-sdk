# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio

# The `view_demo` package published on testnet.
PACKAGE = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4"
# A shared `view_demo::shop::Shop` created when the package was published.
SHOP = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20"


def describe(outputs):
    if outputs.return_values is not None:
        return f"returned {[value.json for value in outputs.return_values]}"
    return f"aborted ({outputs.execution_error.source})"


async def main():
    client = GrpcClient.new_testnet()

    # A single call. `discounted_price` is declared `#[view]` in the package.
    outputs = await client.view_function_call(
        f"{PACKAGE}::shop::discounted_price", None,
        [MoveViewArg.u64(100), MoveViewArg.u64(25)])
    print("discounted_price:", describe(outputs))

    # Three calls in one request: the call from above, the same function with
    # a discount over 100% so that it aborts, and a function that is not
    # declared `#[view]`. Each call runs on its own, so the rejected one does
    # not affect the others.
    results = await client.view_function_calls([
        ViewFunctionCallInput(
            f"{PACKAGE}::shop::discounted_price",
            call_args=[MoveViewArg.u64(100),
                       MoveViewArg.u64(25)]),
        ViewFunctionCallInput(
            f"{PACKAGE}::shop::discounted_price",
            call_args=[MoveViewArg.u64(100),
                       MoveViewArg.u64(200)]),
        ViewFunctionCallInput(f"{PACKAGE}::shop::record_sale",
                              call_args=[
                                  MoveViewArg.object_id(
                                      ObjectId.from_hex(SHOP)),
                                  MoveViewArg.u64(5)
                              ]),
    ])

    for name, result in zip(["priced", "over-discounted", "record_sale"],
                            results):
        if result.outputs is not None:
            print(f"{name}:", describe(result.outputs))
        else:
            print(f"{name}: rejected by the node ({result.error})")


if __name__ == "__main__":
    asyncio.run(main())
