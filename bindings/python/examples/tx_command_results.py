# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    sender = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    builder = client.transaction_builder(sender)

    package_addr = Address.std()
    module_name = Identifier("u64")
    function_name = Identifier("max")

    builder.move_call(
        package_addr,
        module_name,
        function_name,
        [PtbArgument.u64(0), PtbArgument.u64(1000)],
        # Assign a name to the result of this command
        names=["res0"],
    )

    builder.move_call(
        package_addr,
        module_name,
        function_name,
        [PtbArgument.u64(1000), PtbArgument.u64(2000)],
        # Assign a name to the result of this command
        names=["res1"],
    )

    builder.split_coins(
        PtbArgument.gas(),
        # Use the assigned results of previous commands as arguments
        [PtbArgument.assigned("res0"),
         PtbArgument.assigned("res1")],
        # For nested results, a tuple or vec can be used to assign them
        ["coin0", "coin1"],
    )

    # Use assigned results as arguments
    builder.transfer_objects(
        sender, [PtbArgument.assigned("coin0"),
                 PtbArgument.assigned("coin1")])

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_tx(txn, False)
    if res.error is not None:
        raise Exception("Failed to send tx:", res.error)

    print("Tx dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
