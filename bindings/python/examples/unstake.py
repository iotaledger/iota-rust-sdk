# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import sys
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    staked_iotas = await client.objects(
        filter=ObjectFilter(type_tag=str(StructTag.new_staked_iota()))
    )
    if len(staked_iotas.data) == 0:
        raise Exception("no staked iotas found")
    staked_iota = staked_iotas.data[0]

    builder = await TransactionBuilder.init(
        staked_iota.owner().as_address(), client
    )

    builder.unstake(PtbArgument.object_id(staked_iota.object_id()))

    res = await builder.dry_run()
    if res.error is not None:
        raise Exception("Failed to unstake:", res.error)

    print("Unstake dry run was successful!")

if __name__ == "__main__":
    asyncio.run(main())
