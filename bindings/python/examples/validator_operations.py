# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

"""
Example: Validator Operations

Demonstrates querying and analyzing validators.
"""

from lib.iota_sdk import *
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    print("=== Validator Operations Example ===\n")

    # Step 1: Query validators
    print("1. Querying active validators...")
    validators = await client.active_validators(None, {})
    print(f"   Found {len(validators['data'])} active validators\n")

    # Step 2: Display validator info
    print("2. Validator Information:")
    for idx, validator in enumerate(validators['data'][:5], 1):
        print(f"\n   Validator #{idx}:")
        if 'name' in validator and validator['name']:
            print(f"     Name: {validator['name']}")
        print(f"     Address: {validator['address']['address']}")
        print(f"     Voting Power: {validator['voting_power']}")

        if 'nextEpochStakeApy' in validator and validator['nextEpochStakeApy']:
            print(f"     Staking APY: {validator['nextEpochStakeApy']:.2f}%")

        print(f"     Pending Stake: {validator['pendingStake']} MIST")
        print(f"     Pending Withdraw: {validator['pendingWithdraw']} MIST")

    # Step 3: Best practices
    print("\n3. Validator Selection Criteria:")
    print("   - Check commission rates")
    print("   - Review voting power")
    print("   - Consider uptime")
    print("   - Evaluate staking APY")
    print("   - Assess reputation\n")

    # Step 4: Staking workflow
    print("4. Staking Workflow:")
    print("   a. Choose validator")
    print("   b. Prepare transaction")
    print("   c. Sign and submit")
    print("   d. Monitor rewards")
    print("   e. Unstake when needed\n")

    print("Validator operations example completed!")


if __name__ == "__main__":
    asyncio.run(main())
