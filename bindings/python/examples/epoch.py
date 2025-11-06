# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import sys
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    # Get current epoch
    current_epoch = await client.epoch()
    if current_epoch is None:
        raise Exception("missing current epoch")

    print(f"Current epoch: {current_epoch.epoch_id}")
    print(f"Current epoch start time: {current_epoch.start_timestamp}")

    # Get previous epoch
    previous_epoch_id = current_epoch.epoch_id - 1
    previous_epoch = await client.epoch(previous_epoch_id)
    if previous_epoch is None:
        raise Exception("missing previous epoch")

    print(f"Previous epoch: {previous_epoch.epoch_id}")
    if previous_epoch.total_stake_rewards is not None:
        print(
            f"Previous epoch stake rewards: {previous_epoch.total_stake_rewards}"
        )


if __name__ == "__main__":
    asyncio.run(main())
