# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    try:
        client = GraphQlClient.new_devnet()

        from_address = Address.from_hex(
            "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
        )
        to_address = Address.from_hex(
            "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
        )
        obj_ids = [
            ObjectId.from_hex(
                "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
            ),
            ObjectId.from_hex(
                "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
            ),
            ObjectId.from_hex(
                "0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9"
            ),
        ]
        objs_to_transfer = []
        for obj_id in obj_ids:
            obj = await client.object(obj_id)
            if obj == None:
                raise Exception("Missing object:", obj_id)
            objs_to_transfer.append(PtbArgument.object_ref(obj.object_ref()))

        gas_coin_id = ObjectId.from_hex(
            "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
        )
        gas_coin = await client.object(gas_coin_id)
        if gas_coin == None:
            raise Exception("Missing gas coin:", gas_coin)
        gas_price = await client.reference_gas_price() or 100

        builder = TransactionBuilder(from_address)
        builder.transfer_objects(
            to_address,
            objs_to_transfer,
        )
        builder.gas(gas_coin.object_ref()).gas_price(gas_price).gas_budget(500000000)

        txn = builder.finish()

        print("Signing Digest:", txn.signing_digest_hex())
        print("Txn Bytes:", txn.to_base64())

        res = await client.dry_run_tx(txn)
        if res.error is not None:
            raise Exception("Failed to transfer objects:", res.error)

        print("Transfer objects dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
