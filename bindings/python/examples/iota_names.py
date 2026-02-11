# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    name = "name.iota"
    print(f"Resolving name: {name}")

    resolved_address = await client.iota_names_lookup(name)
    if resolved_address is None:
        print(f"No address resolved for {name}")
        return

    print(f"Resolved address: {resolved_address.to_hex()}")

    default_name_dot = await client.iota_names_default_name(
        resolved_address,
        NameFormat.DOT,
    )
    if default_name_dot is None:
        print("No default dot-format name found")
    else:
        print(f"Default name (dot): {default_name_dot}")

    default_name_at = await client.iota_names_default_name(
        resolved_address,
        NameFormat.AT,
    )
    if default_name_at is None:
        print("No default at-format name found")
    else:
        print(f"Default name (at): {default_name_at.format(NameFormat.AT)}")

    registrations = await client.iota_names_registrations(
        resolved_address,
        PaginationFilter(direction=Direction.FORWARD, limit=10),
    )

    if len(registrations.data) == 0:
        print("No IOTA Names registrations found for this address")
        return

    print(f"Registrations ({len(registrations.data)}):")
    for registration in registrations.data:
        print(
            f"- {registration.name_str()} "
            f"(id: {registration.id().to_hex()}, "
            f"expires_at_ms: {registration.expiration_timestamp_ms()})"
        )


if __name__ == "__main__":
    asyncio.run(main())
