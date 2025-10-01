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

        coin_id = ObjectId.from_hex(
            "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
        )

        gas_coin_id = ObjectId.from_hex(
            "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
        )

        builder = await TransactionBuilder.init(my_address, client)

        builder.move_call(
            Address.from_hex("0x3"),
            Identifier("iota_system"),
            Identifier("request_add_stake"),
            [
                PtbArgument.shared_mut(ObjectId.from_hex("0x5")),
                PtbArgument.object_id(coin_id),
                PtbArgument.address(validator.address),
            ],
        )
        builder.gas(gas_coin_id).gas_budget(1000000000)

        res = await builder.dry_run()
        if res.error is not None:
            raise Exception("Failed to stake:", res.error)

        print("Stake dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
