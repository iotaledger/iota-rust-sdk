# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    # ===========================================================================
    # Example 1: Using move_view_call() for blake2b256 hash function
    # ===========================================================================
    print("=== Example 1: move_view_call() for blake2b256 ===")
    print()

    hash_args = [
        "[0,1,2]",
    ]

    result = await client.move_view_call("0x2::hash::blake2b256", None,
                                         hash_args)

    if result.error is not None:
        print("Error:", result.error)
    elif result.results is not None:
        print("Results:", result.results)
    else:
        print("No results")

    # ===========================================================================
    # Example 2: Using move_view_call() for auction metadata
    # ===========================================================================
    print()
    print("=== Example 2: move_view_call() for auction ===")
    print()

    auction_args = [
        "0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b",
        "auc.iota"
    ]

    auction_result = await client.move_view_call(
        "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
        None, auction_args)

    if auction_result.error is not None:
        print("Auction Error:", auction_result.error)
    elif auction_result.results is not None:
        print("Auction Results:", auction_result.results)
    else:
        print("No auction results")


if __name__ == "__main__":
    asyncio.run(main())
