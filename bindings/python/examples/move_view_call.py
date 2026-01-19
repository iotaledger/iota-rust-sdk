# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    arguments = [
        "0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b",
        "auc.iota"
    ]

    result = await client.move_view_call(
        "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
        None, arguments)

    if result.error is not None:
        print("Error:", result.error)
    elif result.results is not None:
        print("Results:", result.results)
    else:
        print("No results")

    arguments = [
        "[0,1,2]",
    ]

    result = await client.move_view_call("0x2::hash::blake2b256", None,
                                         arguments)

    if result.error is not None:
        print("Error:", result.error)
    elif result.results is not None:
        print("Results:", result.results)
    else:
        print("No results")

    # Using TransactionBuilder for move view call
    print("Using TransactionBuilder for move view call:")
    tx_builder = TransactionBuilder(Address.zero()).with_client(client)

    tx_builder.move_call(
        Address.from_hex(
            "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50"
        ),
        Identifier("auction"),
        Identifier("get_auction_metadata"),
        [
            PtbArgument.object_id_from_hex(
                "0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b"
            ),
            PtbArgument.string("\"auc.iota\""),
        ],
    )

    result = await tx_builder.move_view_call()

    if result.error is not None:
        print("Tx Builder Error:", result.error)
    elif result.results is not None:
        print("Tx Builder Results:", result.results)
    else:
        print("No tx builder results")


if __name__ == "__main__":
    asyncio.run(main())
