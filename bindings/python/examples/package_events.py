# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    events = await client.events(
        EventFilter(
            event_type=
            "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba::registry::NameRecordAddedEvent"
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
