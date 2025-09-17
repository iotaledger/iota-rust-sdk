# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import asyncio

from lib.iota_sdk_ffi import *


async def main():
    client = GraphQlClient.new_devnet()

    sender = Address.from_hex(
        "0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e"
    )
    gas_coin_id = ObjectId.from_hex(
        "0xa1d009e8dafe20b1cba05e08aea488aafae1f89d892c3eaef6c0994e155e441a"
    )

    builder = await TransactionBuilder.build(sender, client)

    builder.make_move_vec(
        [
            PtbArgument.address(
                Address.from_hex(
                    "0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e"
                )
            ),
            PtbArgument.address(
                Address.from_hex(
                    "0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3"
                )
            ),
        ],
        TypeTag.new_address(),
        "addresses",
    )
    builder.make_move_vec(
        [
            PtbArgument.u64(10_000_000),
            PtbArgument.u64(20_000_000),
        ],
        TypeTag.new_u64(),
        "amounts",
    )

    builder.move_call(
        Address.from_hex("0x2"),
        Identifier("vec_map"),
        Identifier("from_keys_values"),
        [PtbArgument.res("addresses"), PtbArgument.res("amounts")],
        [TypeTag.new_address(), TypeTag.new_u64()],
    )

    builder.gas(gas_coin_id).gas_budget(1000000000)

    res = await builder.dry_run()

    if res.error is not None:
        raise Exception(f"Failed to call generic Move function: {res.error}")

    print("Successfully called generic Move function!")


if __name__ == "__main__":
    asyncio.run(main())
