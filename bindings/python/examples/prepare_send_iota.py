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
        builder.transfer_objects(
            [builder.input(UnresolvedInput.from_object(coin).with_owned_kind())],
            builder.input(UnresolvedInput.new_pure(to_address.to_bytes())),
        )
        builder.set_sender(from_address)
        builder.set_gas_budget(50000000)
        builder.set_gas_price(await client.reference_gas_price() or 100)
        builder.add_gas_objects(
            [UnresolvedInput.from_object(gas_coin).with_owned_kind()]
        )

        txn = builder.finish()

        print("Signing Digest:", hex_encode(txn.signing_digest()))
        print("Txn Bytes:", base64_encode(txn.bcs_serialize()))

        res = await client.dry_run_tx(txn)
        if res.error is not None:
            raise Exception("Failed to send IOTA:", res.error)

        print("Send IOTA dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
