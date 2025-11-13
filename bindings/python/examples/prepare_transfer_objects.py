# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    from_address = Address.from_hex(
        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
    to_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    objs_to_transfer = [
        PtbArgument.object_id_from_hex(
            "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
        ),
        PtbArgument.object_id_from_hex(
            "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
        ),
        PtbArgument.object_id_from_hex(
            "0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9"
        ),
    ]

    builder = TransactionBuilder(from_address).with_client(client)
    builder.transfer_objects(
        to_address,
        objs_to_transfer,
    )

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_tx(txn)
    if res.error is not None:
        raise Exception("Failed to transfer objects:", res.error)

    print("Transfer objects dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
