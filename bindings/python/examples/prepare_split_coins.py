# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    sender = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    coin_id = ObjectId.from_hex(
        "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")

    builder = client.transaction_builder(sender)

    builder.split_coins(
        PtbArgument.object_id(coin_id),
        [PtbArgument.u64(1000),
         PtbArgument.u64(2000),
         PtbArgument.u64(3000)],
        ["coin1", "coin2", "coin3"],
    ).transfer_objects(
        sender,
        [
            PtbArgument.assigned("coin1"),
            PtbArgument.assigned("coin2"),
            PtbArgument.assigned("coin3"),
        ],
    )

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await builder.dry_run()
    if res.error is not None:
        raise Exception("Failed to split coins:", res.error)

    print("Split coins dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
