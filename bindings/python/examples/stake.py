# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    try:
        client = GraphQlClient.new_devnet()

        my_address = Address.from_hex(
            "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
        )

        validators = await client.active_validators()
        if len(validators.data) == 0:
            raise Exception("no validators found")
        validator = validators.data[0]

        print("Staking to validator", validator.name or "with no name")

        coin = await client.object(
            ObjectId.from_hex(
                "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
            )
        )
        if coin is None:
            raise Exception("missing coin")

        gas_coin = await client.object(
            ObjectId.from_hex(
                "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
            )
        )
        if gas_coin is None:
            raise Exception("missing gas coin")

        builder = TransactionBuilder()
        inputs = [
            builder.input(
                UnresolvedInput.new_shared(ObjectId.from_hex("0x5"), 1, True)
            ),
            builder.input(UnresolvedInput.from_object(coin).with_owned_kind()),
            builder.input(UnresolvedInput.new_pure(validator.address.to_bytes())),
        ]
        builder.move_call(
            Function(
                package=Address.from_hex("0x3"),
                module=Identifier("iota_system"),
                function=Identifier("request_add_stake"),
            ),
            inputs,
        )
        builder.set_sender(my_address)
        builder.set_gas_budget(50000000)
        builder.set_gas_price(await client.reference_gas_price() or 100)
        builder.add_gas_objects(
            [UnresolvedInput.from_object(gas_coin).with_owned_kind()]
        )

        txn = builder.finish()
        res = await client.dry_run_tx(txn)
        if res.error is not None:
            raise Exception("Failed to stake:", res.error)

        print("Stake dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
