# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# Decode `StakedIota` objects into typed Python values.
#
# The GraphQL client returns each object's contents as raw BCS bytes. A single
# `StakedIota.try_from_object(obj)` call gives typed, named-field access to
# id / pool_id / stake_activation_epoch / principal.

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    owner = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    page = await client.objects(filter=ObjectFilter(
        type_tag="0x3::staking_pool::StakedIota", owner=owner))

    if len(page.data) == 0:
        print(f"No StakedIota objects owned by {owner.to_hex()} right now.")
        return

    print(f"Decoded {len(page.data)} StakedIota object(s):\n")
    total_principal = 0
    for obj in page.data:
        staked = StakedIota.try_from_object(obj)
        total_principal += staked.principal()
        print(f"- id:               {staked.id().to_hex()}")
        print(f"  pool_id:          {staked.pool_id().to_hex()}")
        print(f"  stake_activation_epoch: {staked.stake_activation_epoch()}")
        print(f"  principal (nanos): {staked.principal()}")
        print()

    print(f"Total principal across page: {total_principal} nanos")


if __name__ == "__main__":
    asyncio.run(main())
