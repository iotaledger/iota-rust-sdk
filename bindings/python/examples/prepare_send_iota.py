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

        builder = await TransactionBuilder.init(from_address, client)
        builder.send_iota(to_address, PtbArgument.u64(5000000000))

        txn = await builder.finish()

        print("Signing Digest:", txn.signing_digest_hex())
        print("Txn Bytes:", txn.to_base64())

        res = await client.dry_run_tx(txn)
        if res.error is not None:
            raise Exception("Failed to send IOTA:", res.error)

        print("Send IOTA dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
