# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

"""
Example: Event Monitoring

Demonstrates querying and monitoring blockchain events.
"""

from lib.iota_sdk import *
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    print("=== Event Monitoring Example ===\n")

    # Step 1: Understanding events
    print("1. Events in IOTA:")
    print("   - Emitted by Move functions")
    print("   - Track on-chain activities")
    print("   - Build reactive apps")
    print("   - Filterable and queryable\n")

    # Step 2: Event structure
    print("2. Event Structure:")
    print("   - Event type (module::name)")
    print("   - Sender address")
    print("   - Timestamp")
    print("   - Event data (BCS)\n")

    # Step 3: Querying methods
    print("3. Querying Events:")
    print("   Methods:")
    print("   a. By transaction digest")
    print("   b. By event type")
    print("   c. By sender")
    print("   d. By time range")
    print("   e. With pagination\n")

    # Step 4: Filtering
    print("4. Filtering Strategies:")
    print("   - By package ID")
    print("   - By module")
    print("   - By event type")
    print("   - Combine filters\n")

    # Step 5: Patterns
    print("5. Common Monitoring Patterns:")
    print("   - Token transfers")
    print("   - Staking events")
    print("   - DEX trades")
    print("   - Governance events\n")

    # Step 6: Best practices
    print("6. Best Practices:")
    print("   - Use pagination")
    print("   - Cache locally")
    print("   - Handle ordering")
    print("   - Checkpoint monitoring")
    print("   - Retry logic\n")

    # Step 7: Use cases
    print("7. Real-World Use Cases:")
    print("   - Portfolio tracking")
    print("   - Notifications")
    print("   - Analytics")
    print("   - Event-driven systems\n")

    print("Event monitoring example completed!")


if __name__ == "__main__":
    asyncio.run(main())
