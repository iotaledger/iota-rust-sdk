# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    try:
        client = GraphQlClient.new_devnet()

        staked_iotas = await client.objects(
            filter=ObjectFilter(type_tag="0x3::staking_pool::StakedIota")
        )
        if len(staked_iotas.data) == 0:
            raise Exception("no staked iotas found")
        staked_iota = staked_iotas.data[0]

        gas_coins = await client.objects(
            ObjectFilter(
                type_tag=str(StructTag.gas_coin()),
                owner=staked_iota.owner().as_address(),
            )
        )
        if len(gas_coins.data) == 0:
            raise Exception("no gas coin found")
        gas_coin = gas_coins.data[0]

        builder = await TransactionBuilder.init(gas_coin.owner().as_address(), client)

        builder.move_call(
            Address.from_hex("0x3"),
            Identifier("iota_system"),
            Identifier("request_withdraw_stake"),
            [
                PtbArgument.shared_mut(ObjectId.from_hex("0x5")),
                PtbArgument.object_id(staked_iota.object_id()),
            ],
        )
        builder.gas(gas_coin.object_id())

        res = await builder.dry_run()
        if res.error is not None:
            raise Exception("Failed to unstake:", res.error)

        print("Unstake dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
