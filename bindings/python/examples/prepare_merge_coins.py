# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import sys
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    sender = Address.from_hex(
        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
    )

    coin_0 = PtbArgument.object_id_from_hex(
        "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
    )
    coin_1 = PtbArgument.object_id_from_hex(
        "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
    )

    builder = await TransactionBuilder.init(sender, client)

    builder.merge_coins(coin_0, [coin_1])

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await builder.dry_run()
    if res.error is not None:
        raise Exception("Failed to merge coins:", res.error)

    print("Merge coins dry run was successful!")

if __name__ == "__main__":
    asyncio.run(main())
