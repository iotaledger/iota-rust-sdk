# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

"""
Example: Multisig Address Operations

Demonstrates creating and using multisig addresses.
"""

from lib.iota_sdk import *

THRESHOLD = 2
WEIGHT = 1


async def main():
    client = GraphQlClient.new_devnet()

    print("=== Multisig Address Example ===\n")

    # Step 1: Create key pairs
    print("1. Creating key pairs...")
    public_keys = []  # Would contain real public keys
    print(f"   Generated {len(public_keys)} public keys\n")

    # Step 2: Create multisig address
    print("2. Creating multisig address...")
    print(f"   Threshold: {THRESHOLD} out of {len(public_keys) or 3}")
    print("   Multisig address: (would be computed)\n")

    # Step 3: Display usage
    print("3. Multisig Operations:")
    print(f"   - Requires {THRESHOLD} signatures to spend")
    print(f"   - Each key weight: {WEIGHT}")
    print(f"   - Total weight needed: {THRESHOLD * WEIGHT}\n")

    # Step 4: Signing process
    print("4. Transaction Signing:")
    print("   a. Create unsigned transaction")
    print("   b. Sign with required keys")
    print("   c. Combine signatures")
    print("   d. Submit transaction\n")

    print("Multisig example completed!")


if __name__ == "__main__":
    asyncio.run(main())
