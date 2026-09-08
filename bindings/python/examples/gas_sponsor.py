# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    sender = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    sponsor = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    builder = client.transaction_builder(sender)

    package_addr = Address.std()
    module_name = Identifier("u8")
    function_name = Identifier("max")

    builder.move_call(
        package_addr,
        module_name,
        function_name,
        [PtbArgument.u8(0), PtbArgument.u8(1)],
    )

    builder.sponsor(sponsor)

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_transaction(txn)
    if res.error is not None:
        raise Exception("Failed to send gas sponsor tx:", res.error)

    print("Gas sponsor tx dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
