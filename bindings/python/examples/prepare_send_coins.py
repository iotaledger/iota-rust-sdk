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

    # This is a coin of type
    # 0xfce9c14e5f0c2b65787debb8145a33a4a2fc83152e8939000b862e174bc86bb8::cert::CERT
    coin_id = PtbArgument.object_id_from_hex(
        "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2")

    builder = client.transaction_builder(from_address)
    builder.send_coins(
        [coin_id],
        to_address,
        PtbArgument.u64(50000000000),
    )

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await builder.dry_run()
    if res.error is not None:
        raise Exception("Failed to send coins:", res.error)

    print("Send coins dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
