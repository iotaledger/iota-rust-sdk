# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

"""
Example: Shared Object Operations

Demonstrates working with shared objects in IOTA.
"""

from lib.iota_sdk import *
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    print("=== Shared Object Operations Example ===\n")

    # Step 1: Overview
    print("1. Shared Objects Overview:")
    print("   - Can be accessed by anyone")
    print("   - Multiple transactions can use concurrently")
    print("   - Require special handling")
    print("   - Examples: pools, registries\n")

    # Step 2: Shared vs Owned
    print("2. Shared vs Owned Objects:")
    print("   Owned Objects:")
    print("     - Single owner controls access")
    print("     - Only owner can use")
    print("     - Simpler handling\n")
    print("   Shared Objects:")
    print("     - No single owner")
    print("     - Anyone can use")
    print("     - Requires shared references\n")

    # Step 3: Querying
    print("3. Querying Shared Objects:")
    print("   - Use object() to fetch details")
    print("   - Check shared ownership")
    print("   - Identify type and structure\n")

    # Step 4: Transaction patterns
    print("4. Transaction Patterns:")
    print("   a. Move call with shared object")
    print("   b. Multiple shared objects")
    print("   c. Mixing shared and owned")
    print("   d. Concurrency best practices\n")

    # Step 5: Use cases
    print("5. Common Use Cases:")
    print("   - DEX liquidity pools")
    print("   - Shared registries")
    print("   - Governance contracts")
    print("   - Public state\n")

    # Step 6: Best practices
    print("6. Best Practices:")
    print("   - Minimize shared object usage")
    print("   - Design for concurrent access")
    print("   - Handle contention")
    print("   - Consider gas costs\n")

    print("Shared objects example completed!")


if __name__ == "__main__":
    asyncio.run(main())
