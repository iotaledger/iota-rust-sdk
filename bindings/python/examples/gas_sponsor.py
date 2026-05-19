# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    sender = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    sponsor = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        sponsor, client)

    builder = TransactionBuilder(sender).with_client(client)

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

    res = await client.dry_run_tx(txn, False)
    if res.error is not None:
        raise Exception("Failed to send gas sponsor tx:", res.error)

    print("Gas sponsor tx dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
