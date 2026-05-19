# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    # Query events emitted by the validator-set module in the IOTA system
    # framework (0x3). These fire on every epoch change so they are reliably
    # present on every network including localnet.
    events = await client.events(
        EventFilter(event_type="0x3::validator::StakingRequestEvent"),
        PaginationFilter(direction=Direction.FORWARD, limit=10),
    )

    for event in events.data:
        print(f"Type: {event.type}")
        if event.sender is not None:
            print(f"Sender: {event.sender.to_hex()}")
        if event.module is not None:
            print(f"Module: {event.module}")
        print(f"JSON: {event.json}")


if __name__ == "__main__":
    asyncio.run(main())
