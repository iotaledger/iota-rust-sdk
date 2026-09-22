# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    sender = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    coin_0 = PtbArgument.object_id_from_hex(
        "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")
    coin_1 = PtbArgument.object_id_from_hex(
        "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")

    builder = client.transaction_builder(sender)

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
