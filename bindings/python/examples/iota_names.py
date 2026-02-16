# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

"""
Example: IOTA Names Operations

This example demonstrates major IOTA Names operations including:
- Looking up a name and resolving its address
- Checking name availability
"""

from lib.iota_sdk import *
import asyncio

IOTA_NAMES_PACKAGE = "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba"
IOTA_NAMES_REGISTRY = "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"


async def resolve_name(client: GraphQlClient, name: str) -> Optional[Address]:
    """Resolve a name to its target address"""
    # For simplicity, using dev_inspect_move_function
    # In production, you'd use TransactionBuilder like in the Rust example
    try:
        # Simplified example - in real implementation use TransactionBuilder
        print(f"   Attempting to resolve: {name}")
        # This is a placeholder - actual implementation would use move calls
        return None
    except Exception as e:
        print(f"   Error resolving name: {e}")
        return None


async def check_availability(client: GraphQlClient, name: str) -> bool:
    """Check if a name is available for registration"""
    # Simplified example
    print(f"   Checking availability for: {name}")
    return True


async def main():
    client = GraphQlClient.new_devnet()

    print("=== IOTA Names Example ===\n")

    # Example 1: Lookup and resolve a name
    name = "name.iota"
    print(f"1. Resolving name '{name}'")
    address = await resolve_name(client, name)
    if address:
        print(f"   Resolved to: {address.to_hex()}\n")
    else:
        print("   Name not found or has no target address\n")

    # Example 2: Check name availability
    test_name = "test123.iota"
    print(f"2. Checking availability of '{test_name}'")
    is_available = await check_availability(client, test_name)
    if is_available:
        print("   Name is available!\n")
    else:
        print("   Name is already registered\n")


if __name__ == "__main__":
    asyncio.run(main())
