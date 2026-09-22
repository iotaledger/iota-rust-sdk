# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    from_address = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    to_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    builder = client.transaction_builder(from_address)
    builder.send_iota(to_address, PtbArgument.u64(5000000000))

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_transaction(txn)
    if res.error is not None:
        raise Exception("Failed to send IOTA:", res.error)

    print("Send IOTA dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
