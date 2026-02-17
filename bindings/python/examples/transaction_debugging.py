# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

"""
Example: Transaction Debugging

Demonstrates debugging and error handling for transactions.
"""

from lib.iota_sdk import *
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    print("=== Transaction Debugging Example ===\n")

    # Step 1: Common errors
    print("1. Common Transaction Errors:")
    print("   - Insufficient gas")
    print("   - Object not found")
    print("   - Invalid version")
    print("   - Permission denied")
    print("   - Move abort")
    print("   - Type mismatch\n")

    # Step 2: Dry run
    print("2. Using Dry Run:")
    print("   Purpose:")
    print("   - Test before submission")
    print("   - Estimate gas")
    print("   - Safe error checking\n")
    print("   Usage:")
    print("   a. Build transaction")
    print("   b. Call dry_run()")
    print("   c. Check errors")
    print("   d. Review gas\n")

    # Step 3: Error interpretation
    print("3. Error Interpretation:")
    print("   - Read messages carefully")
    print("   - Check abort codes")
    print("   - Verify ownership")
    print("   - Validate types")
    print("   - Check gas budget\n")

    # Step 4: Debugging strategies
    print("4. Debugging Strategies:")
    print("   a. Start with dry run")
    print("   b. Check object states")
    print("   c. Verify sender")
    print("   d. Inspect effects")
    print("   e. Use dev_inspect\n")

    # Step 5: Transaction inspection
    print("5. Transaction Inspection:")
    print("   - Use get_transaction()")
    print("   - Check status")
    print("   - Review effects")
    print("   - Examine changes\n")

    # Step 6: Best practices
    print("6. Best Practices:")
    print("   - Always dry run first")
    print("   - Set gas budget")
    print("   - Handle errors")
    print("   - Log digests")
    print("   - Test incrementally\n")

    print("Transaction debugging example completed!")


if __name__ == "__main__":
    asyncio.run(main())
