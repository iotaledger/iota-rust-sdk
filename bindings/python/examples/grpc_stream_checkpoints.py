# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GrpcClient.new_testnet()

    # Pick a small range of recent checkpoints to stream.
    latest = await client.get_checkpoint_latest()
    start = latest.sequence_number - 4

    stream = await client.stream_checkpoints(start, latest.sequence_number)

    while (checkpoint := await stream.next()) is not None:
        summary = checkpoint.summary
        print(f"Checkpoint {checkpoint.sequence_number}:",
              f"epoch {summary.epoch()},",
              f"{summary.network_total_transactions()} total transactions,",
              f"timestamp {summary.timestamp_ms()}")


if __name__ == "__main__":
    asyncio.run(main())
