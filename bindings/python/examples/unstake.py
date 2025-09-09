# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import asyncio
from lib.iota_sdk_ffi import *


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

        builder = TransactionBuilder()
        inputs = [
            builder.input(
                UnresolvedInput.new_shared(ObjectId.from_hex("0x5"), 1, True)
            ),
            builder.input(UnresolvedInput.from_object(staked_iota).with_owned_kind()),
        ]
        builder.move_call(
            Function(
                package=Address.from_hex("0x3"),
                module=Identifier("iota_system"),
                function=Identifier("request_withdraw_stake"),
            ),
            inputs,
        )
        builder.set_sender(gas_coin.owner().as_address())
        builder.set_gas_budget(50000000)
        builder.set_gas_price(await client.reference_gas_price() or 100)
        builder.add_gas_objects(
            [UnresolvedInput.from_object(gas_coin).with_owned_kind()]
        )

        txn = builder.finish()
        res = await client.dry_run_tx(txn)
        if res.error is not None:
            raise Exception("Failed to unstake:", res.error)

        print("Unstake dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
