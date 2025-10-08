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
        objs_to_transfer = [
            PtbArgument.object_id(
                ObjectId.from_hex(
                    "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
                )
            ),
            PtbArgument.object_id(
                ObjectId.from_hex(
                    "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
                )
            ),
            PtbArgument.object_id(
                ObjectId.from_hex(
                    "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
                )
            ),
        ]

        builder = await TransactionBuilder.init(from_address, client)
        builder.transfer_objects(
            to_address,
            objs_to_transfer,
        )

        txn = await builder.finish()

        print("Signing Digest:", hex_encode(txn.signing_digest()))
        print("Txn Bytes:", base64_encode(txn.bcs_serialize()))

        res = await client.dry_run_tx(txn)
        if res.error is not None:
            raise Exception("Failed to transfer objects:", res.error)

        print("Transfer objects dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
