# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    events = await client.events(
        EventFilter(
            event_type=
            "0x7aec8176867a0c8d2803d758ebf98226d301ef0f00393879ea718f6bd1554f16::registry::NameRecordAddedEvent"
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
