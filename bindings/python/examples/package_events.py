# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    events = await client.events(
        EventFilter(
            event_type=
            "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent"
        ),
        PaginationFilter(direction=Direction.FORWARD, limit=10),
    )

    for event in events.data:
        print(f"Type: {event.type}")
        print(f"Sender: {event.sender.to_hex()}")
        print(f"Module: {event.module}")
        print(f"JSON: {event.json}")


if __name__ == "__main__":
    asyncio.run(main())
