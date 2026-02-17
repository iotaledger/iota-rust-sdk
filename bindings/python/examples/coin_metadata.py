# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

"""
Example: Coin Metadata and Operations

Demonstrates working with IOTA coins.
"""

from lib.iota_sdk import *
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    print("=== Coin Metadata Example ===\n")

    # Step 1: Query balances
    print("1. Querying coin balances...")
    print("   Use client.coin_balances(address)\n")

    # Step 2: Coin structure
    print("2. Coin Object Structure:")
    print("   - Separate objects per coin")
    print("   - Type and value\n")

    # Step 3: Operations
    print("3. Common Operations:")
    print("   a. Split coins")
    print("   b. Merge coins")
    print("   c. Transfer\n")

    # Step 4: Best practices
    print("4. Best Practices:")
    print("   - Manage coin count")
    print("   - Merge small coins")
    print("   - Use gas efficiently\n")

    print("Coin metadata example completed!")


if __name__ == "__main__":
    asyncio.run(main())
