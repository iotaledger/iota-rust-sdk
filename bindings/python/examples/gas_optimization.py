# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *
import asyncio

async def main():
    print("=== Gas Optimization Example ===\n")
    print("1. Understanding Gas:")
    print("   - Computation, storage, rebate")
    print("   - Measured in MIST\n")
    print("2. Gas Budgeting:")
    print("   - Use dry_run + 10-20% buffer\n")
    print("3. Optimization:")
    print("   - Batch operations")
    print("   - Minimize objects")
    print("   - Efficient code\n")
    print("4. Storage:")
    print("   - Delete for rebate")
    print("   - Keep objects small\n")
    print("5. Patterns:")
    print("   - Merge coins")
    print("   - Batch transactions\n")
    print("6. Monitoring:")
    print("   - Use dry_run")
    print("   - Check effects\n")
    print("7. Best Practices:")
    print("   - Test first")
    print("   - Set realistic budgets\n")
    print("Gas optimization example completed!")

if __name__ == "__main__":
    asyncio.run(main())
