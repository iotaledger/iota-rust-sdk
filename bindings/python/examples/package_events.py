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
        # Sender and module are optional: some events (such as system- or
        # genesis-emitted ones) carry neither.
        sender = event.sender.to_hex() if event.sender is not None else "none"
        module = event.module if event.module is not None else "none"
        print(f"Type: {event.move_type}")
        print(f"Sender: {sender}")
        print(f"Module: {module}")
        print(f"JSON: {event.json}")


if __name__ == "__main__":
    asyncio.run(main())
