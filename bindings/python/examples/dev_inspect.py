# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    sender = Address.zero()

    builder = TransactionBuilder(sender).with_client(client)

    # Build a small chain of stdlib Move calls and extract the return value
    # from the final command via dry_run.
    builder.move_call(
        Address.std(),
        Identifier("u64"),
        Identifier("max"),
        [PtbArgument.u64(100), PtbArgument.u64(200)],
        names=["max_value"],
    )

    builder.move_call(
        Address.std(),
        Identifier("u64"),
        Identifier("min"),
        [PtbArgument.assigned("max_value"),
         PtbArgument.u64(150)],
        names=["result"],
    )

    res = await builder.dry_run(True)

    if res.error is not None:
        raise Exception(f"Failed to dry-run: {res.error}")

    if len(res.results) > 0:
        last_effect = res.results[-1]
        if len(last_effect.return_values) > 0:
            return_value = last_effect.return_values[0]
            if return_value.type_tag.is_u64() and len(return_value.bcs) == 8:
                value = int.from_bytes(return_value.bcs, byteorder="little")
                print(f"min(max(100, 200), 150) = {value}")
            else:
                print("Failed to extract u64 from results")
        else:
            print("Failed to extract u64 from results")
    else:
        print("Failed to extract u64 from results")


if __name__ == "__main__":
    asyncio.run(main())
