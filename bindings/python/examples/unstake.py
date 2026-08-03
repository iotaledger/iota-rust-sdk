# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    # Filtering by type alone scans every object on the network, which the
    # GraphQL server rejects with a timeout, so filter by owner as well.
    owner = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    staked_iotas = await client.objects(filter=ObjectFilter(
        type_tag=str(StructTag.new_staked_iota()), owner=owner))
    if len(staked_iotas.data) == 0:
        raise Exception("no staked iotas found")
    staked_iota = staked_iotas.data[0]

    builder = TransactionBuilder(
        staked_iota.owner().as_address()).with_client(client)

    builder.unstake(PtbArgument.object_id(staked_iota.id()))

    res = await builder.dry_run()
    if res.error is not None:
        raise Exception("Failed to unstake:", res.error)

    print("Unstake dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
