# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    try:
        client = GraphQlClient.new_devnet()

        sender = Address.from_hex(
            "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
        )

        coin_id = ObjectId.from_hex(
            "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
        )

        builder = await TransactionBuilder.init(sender, client)

        builder.split_coins(
            PtbArgument.object_id(coin_id),
            [PtbArgument.u64(1000), PtbArgument.u64(2000), PtbArgument.u64(3000)],
            ["coin1", "coin2", "coin3"],
        ).transfer_objects(
            sender,
            [
                PtbArgument.res("coin1"),
                PtbArgument.res("coin2"),
                PtbArgument.res("coin3"),
            ],
        ).gas(
            coin_id
        ).gas_budget(
            1000000000
        )

        txn = (await builder.finish()).as_v1()

        print("Signing Digest:", hex_encode(txn.signing_digest()))
        print("Txn Bytes:", base64_encode(txn.bcs_serialize()))

        res = await builder.dry_run()
        if res.error is not None:
            raise Exception("Failed to split coins:", res.error)

        print("Split coins dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
