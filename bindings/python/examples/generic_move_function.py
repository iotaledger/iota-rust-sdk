# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import asyncio

from lib.iota_sdk_ffi import *


async def main():
    client = GraphQlClient.new_devnet()

    sender = Address.from_hex(
        "0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e"
    )
    gas_coin = await client.object(
        ObjectId.from_hex(
            "0xa1d009e8dafe20b1cba05e08aea488aafae1f89d892c3eaef6c0994e155e441a"
        )
    )
    if gas_coin is None:
        raise Exception("missing gas coin")

    builder = TransactionBuilder()

    addresses = builder.make_move_vec(
        TypeTag.new_address(),
        [
            builder.input(
                UnresolvedInput.new_pure(
                    Address.from_hex(
                        "0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e"
                    ).to_bytes(),
                )
            ),
            builder.input(
                UnresolvedInput.new_pure(
                    Address.from_hex(
                        "0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3"
                    ).to_bytes()
                )
            ),
        ],
    )
    balances = builder.make_move_vec(
        TypeTag.new_u64(),
        [
            builder.input(
                UnresolvedInput.new_pure(
                    (10_000_000).to_bytes(8, "little", signed=False)
                )
            ),
            builder.input(
                UnresolvedInput.new_pure(
                    (20_000_000).to_bytes(8, "little", signed=False)
                )
            ),
        ],
    )

    builder.move_call(
        Function(
            package=Address.from_hex("0x2"),
            module=Identifier("vec_map"),
            function=Identifier("from_keys_values"),
            type_args=[TypeTag.new_address(), TypeTag.new_u64()],
        ),
        [addresses, balances],
    )
    builder.set_sender(sender)
    builder.set_gas_budget(50_000_000)
    builder.set_gas_price(await client.reference_gas_price())
    builder.add_gas_objects([UnresolvedInput.from_object(gas_coin).with_owned_kind()])

    txn = builder.finish()
    res = await client.dry_run_tx(txn, False)

    if res.error is not None:
        raise Exception(f"Failed to call generic Move function: {res.error}")

    print("Successfully called generic Move function!")


if __name__ == "__main__":
    asyncio.run(main())
