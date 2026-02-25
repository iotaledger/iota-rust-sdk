# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# This example demonstrates the major IOTA Names operations:
#
# 1. Name lookup: resolve an IOTA name to an address
# 2. Reverse lookup: resolve an address back to its IOTA name
# 3. Name record details: query expiration timestamp
# 4. Check existence: verify if a name is registered
#
# All operations use dev_inspect (dry run) so no gas or signing is needed.

from lib.iota_sdk import *

import asyncio


# IOTA Names package address and shared object ID on devnet
IOTA_NAMES_PACKAGE = "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba"
IOTA_NAMES_OBJECT = "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"


def registry_type_tag(pkg):
    return TypeTag.new_struct(
        StructTag(pkg, Identifier("registry"), Identifier("Registry")))


def name_record_type_tag(pkg):
    return TypeTag.new_struct(
        StructTag(pkg, Identifier("name_record"), Identifier("NameRecord")))


async def lookup_name(client, name):
    """Example 1: Look up an IOTA name to get the associated address."""
    pkg = Address.from_hex(IOTA_NAMES_PACKAGE)
    obj = ObjectId.from_hex(IOTA_NAMES_OBJECT)
    std = Address.std()
    sender = Address.zero()

    builder = TransactionBuilder(sender).with_client(client)

    # 1. Get the registry
    builder.move_call(
        pkg, Identifier("iota_names"), Identifier("registry"),
        [PtbArgument.shared_mut(obj)],
        [registry_type_tag(pkg)],
        ["iota_names"],
    )

    # 2. Create name from string
    builder.move_call(
        pkg, Identifier("name"), Identifier("new"),
        [PtbArgument.string(name)],
        names=["name"],
    )

    # 3. Lookup name record
    builder.move_call(
        pkg, Identifier("registry"), Identifier("lookup"),
        [PtbArgument.assigned("iota_names"), PtbArgument.assigned("name")],
        names=["name_record_opt"],
    )

    # 4. Borrow name record from option
    builder.move_call(
        std, Identifier("option"), Identifier("borrow"),
        [PtbArgument.assigned("name_record_opt")],
        [name_record_type_tag(pkg)],
        ["name_record"],
    )

    # 5. Get target address from name record
    builder.move_call(
        pkg, Identifier("name_record"), Identifier("target_address"),
        [PtbArgument.assigned("name_record")],
        names=["target_address_opt"],
    )

    # 6. Borrow address from option
    builder.move_call(
        std, Identifier("option"), Identifier("borrow"),
        [PtbArgument.assigned("target_address_opt")],
        [TypeTag.new_address()],
        ["target_address"],
    )

    res = await builder.dry_run(True)

    if res.error is not None:
        if "None" in res.error or "option" in res.error:
            return None
        raise Exception(f"Name lookup failed: {res.error}")

    if len(res.results) > 0:
        last_effect = res.results[-1]
        if len(last_effect.return_values) > 0:
            rv = last_effect.return_values[0]
            if rv.type_tag.is_address() and len(rv.bcs) == 32:
                return Address.from_bytes(rv.bcs)
    return None


async def reverse_lookup(client, address):
    """Example 2: Reverse lookup - resolve an address to its IOTA name."""
    pkg = Address.from_hex(IOTA_NAMES_PACKAGE)
    obj = ObjectId.from_hex(IOTA_NAMES_OBJECT)
    sender = Address.zero()

    builder = TransactionBuilder(sender).with_client(client)

    # Get the shared registry
    builder.move_call(
        pkg, Identifier("iota_names"), Identifier("registry"),
        [PtbArgument.shared_mut(obj)],
        [registry_type_tag(pkg)],
        ["registry"],
    )

    # Reverse lookup: address -> Option<Name>
    builder.move_call(
        pkg, Identifier("registry"), Identifier("reverse_lookup"),
        [PtbArgument.assigned("registry"), PtbArgument.address(address)],
        names=["name_opt"],
    )

    res = await builder.dry_run(True)

    if res.error is not None:
        print(f"  Reverse lookup failed: {res.error}")
        return

    if len(res.results) > 0:
        rv = res.results[-1].return_values[0] if len(
            res.results[-1].return_values) > 0 else None
        if rv and len(rv.bcs) > 0 and rv.bcs[0] == 1:
            print(f"  Address {address.to_hex()} has a reverse name record")
        else:
            print(
                f"  Address {address.to_hex()} does not have a reverse name record"
            )


async def name_record_details(client, name):
    """Example 3: Query name record details (target address, expiration)."""
    pkg = Address.from_hex(IOTA_NAMES_PACKAGE)
    obj = ObjectId.from_hex(IOTA_NAMES_OBJECT)
    std = Address.std()
    sender = Address.zero()

    builder = TransactionBuilder(sender).with_client(client)

    # Get the shared registry
    builder.move_call(
        pkg, Identifier("iota_names"), Identifier("registry"),
        [PtbArgument.shared_mut(obj)],
        [registry_type_tag(pkg)],
        ["registry"],
    )

    # Create the name object
    builder.move_call(
        pkg, Identifier("name"), Identifier("new"),
        [PtbArgument.string(name)],
        names=["name"],
    )

    # Look up the name record
    builder.move_call(
        pkg, Identifier("registry"), Identifier("lookup"),
        [PtbArgument.assigned("registry"), PtbArgument.assigned("name")],
        names=["name_record_opt"],
    )

    # Borrow the name record from Option
    builder.move_call(
        std, Identifier("option"), Identifier("borrow"),
        [PtbArgument.assigned("name_record_opt")],
        [name_record_type_tag(pkg)],
        ["name_record"],
    )

    # Get the target address
    builder.move_call(
        pkg, Identifier("name_record"), Identifier("target_address"),
        [PtbArgument.assigned("name_record")],
        names=["target_address_opt"],
    )

    # Get the expiration timestamp
    builder.move_call(
        pkg, Identifier("name_record"), Identifier("expiration_timestamp_ms"),
        [PtbArgument.assigned("name_record")],
        names=["expiration"],
    )

    res = await builder.dry_run(True)

    if res.error is not None:
        raise Exception(f"Name record query failed: {res.error}")

    print(f"  Name record details for '{name}':")

    # Extract expiration (u64) from results
    for effect in res.results:
        for rv in effect.return_values:
            if rv.type_tag.is_u64() and len(rv.bcs) == 8:
                timestamp = int.from_bytes(rv.bcs, byteorder='little')
                print(f"  Expiration timestamp (ms): {timestamp}")

    # Extract target address from the Option<address> result (5th move call)
    if len(res.results) > 4:
        rv = res.results[4].return_values[0] if len(
            res.results[4].return_values) > 0 else None
        if rv and len(rv.bcs) == 33 and rv.bcs[0] == 1:
            addr = Address.from_bytes(rv.bcs[1:33])
            print(f"  Target address: {addr.to_hex()}")
        else:
            print("  Target address: not set")


async def check_name_exists(client, name):
    """Example 4: Check if a name exists in the registry."""
    pkg = Address.from_hex(IOTA_NAMES_PACKAGE)
    obj = ObjectId.from_hex(IOTA_NAMES_OBJECT)
    sender = Address.zero()

    builder = TransactionBuilder(sender).with_client(client)

    # Get the shared registry
    builder.move_call(
        pkg, Identifier("iota_names"), Identifier("registry"),
        [PtbArgument.shared_mut(obj)],
        [registry_type_tag(pkg)],
        ["registry"],
    )

    # Create the name object
    builder.move_call(
        pkg, Identifier("name"), Identifier("new"),
        [PtbArgument.string(name)],
        names=["name"],
    )

    # Check if the name has a record
    builder.move_call(
        pkg, Identifier("registry"), Identifier("has_record"),
        [PtbArgument.assigned("registry"), PtbArgument.assigned("name")],
        names=["exists"],
    )

    res = await builder.dry_run(True)

    if res.error is not None:
        raise Exception(f"has_record check failed: {res.error}")

    if len(res.results) > 0:
        rv = res.results[-1].return_values[0] if len(
            res.results[-1].return_values) > 0 else None
        if rv and rv.type_tag.is_bool():
            return rv.bcs[0] == 1
    return False


async def main():
    client = GraphQlClient.new_devnet()
    name = "name.iota"

    print("=== IOTA Names Examples ===\n")

    # Example 1: Name lookup (name -> address)
    print(f"1. Looking up '{name}'...")
    address = await lookup_name(client, name)
    if address:
        print(f"   Resolved to: {address.to_hex()}\n")

        # Example 2: Reverse lookup (address -> name)
        print(f"2. Reverse lookup for {address.to_hex()}...")
        await reverse_lookup(client, address)
        print()
    else:
        print("   Name not found or expired\n")
        print("2. Skipping reverse lookup (no address to look up)\n")

    # Example 3: Name record details
    print(f"3. Querying name record details for '{name}'...")
    await name_record_details(client, name)
    print()

    # Example 4: Check if names exist
    print("4. Checking name existence...")
    exists = await check_name_exists(client, name)
    print(f"   '{name}' exists: {exists}")

    fake_name = "this-name-probably-does-not-exist-12345.iota"
    exists = await check_name_exists(client, fake_name)
    print(f"   '{fake_name}' exists: {exists}")


if __name__ == "__main__":
    asyncio.run(main())
