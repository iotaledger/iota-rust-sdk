# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    # Query with a known sample name and address used across examples.
    name = "auc.iota"
    address = Address.from_hex(
        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
    )

    resolved_address = await client.iota_names_lookup(name)
    if resolved_address is None:
        print(f"No address found for {name}")
    else:
        print(f"Resolved {name} -> {resolved_address.to_hex()}")

    default_name = await client.iota_names_default_name(address, NameFormat.DOT)
    if default_name is None:
        print(f"No default IOTA name configured for {address.to_hex()}")
    else:
        print(f"Default name for {address.to_hex()}: {default_name}")

    registrations_page = await client.iota_names_registrations(
        address,
        PaginationFilter(direction=Direction.FORWARD, limit=10),
    )
    print(f"Name registrations fetched: {len(registrations_page.data)}")
    for registration in registrations_page.data:
        print(
            f"- {registration.name_str()} "
            f"(id: {registration.id().to_hex()}, "
            f"expires_at_ms: {registration.expiration_timestamp_ms()})"
        )


if __name__ == "__main__":
    asyncio.run(main())
