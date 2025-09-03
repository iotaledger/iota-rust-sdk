# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import asyncio
from lib.iota_sdk_ffi import GraphQlClient


async def main():
    try:
        client = GraphQlClient.new_devnet()

        # Get current epoch
        current_epoch = await client.epoch(None)
        if current_epoch is None:
            print("Current epoch is None")
            return

        print(f"Current epoch: {current_epoch.epoch_id}")
        print(f"Current epoch start time: {current_epoch.start_timestamp}")

        # Get previous epoch
        previous_epoch_id = current_epoch.epoch_id - 1
        previous_epoch = await client.epoch(previous_epoch_id)
        if previous_epoch is None:
            print("Previous epoch is None")
            return

        print(f"Previous epoch: {previous_epoch.epoch_id}")
        if previous_epoch.total_stake_rewards is not None:
            print(f"Previous epoch stake rewards: {previous_epoch.total_stake_rewards}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
