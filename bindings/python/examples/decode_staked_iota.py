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

    # Filtering objects by type alone scans every object on the network, which
    # the GraphQL server rejects with a timeout. Pick a recent staker and filter
    # by owner as well, so only that address' objects are looked at.
    stake_filter = TransactionsFilter(
        function="0x3::iota_system::request_add_stake")
    latest = PaginationFilter(direction=Direction.BACKWARD, limit=1)
    stakers = await client.transactions(filter=stake_filter,
                                        pagination_filter=latest)

    if len(stakers.data) == 0:
        print("No staking transactions on testnet right now.")
        return

    staker = stakers.data[-1].transaction.sender()
    print(f"Latest staker: {staker.to_hex()}\n")

    page = await client.objects(filter=ObjectFilter(
        type_tag="0x3::staking_pool::StakedIota", owner=staker))

    if len(page.data) == 0:
        print(f"No StakedIota objects owned by {staker.to_hex()} right now.")
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
