# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio

HOW_MANY = 5


async def main():
    client = GrpcClient.new_testnet()

    # Pick a starting point a few checkpoints behind head so the example
    # returns promptly instead of waiting on new blocks.
    head = (await client.checkpoint_latest()).sequence_number
    start = max(head - (HOW_MANY - 1), 0)
    end = head

    # Only ask for the summary — keeps the message small. Pass `None` (or
    # compose more fields) to pull more data per checkpoint.
    stream = await client.checkpoints_stream(start, end, ["checkpoint.summary"])

    print(f"Streaming checkpoints {start}..={end}")
    while (checkpoint := await stream.next()) is not None:
        summary = checkpoint.summary
        print(f"  cp {checkpoint.sequence_number:>6}  "
              f"epoch {summary.epoch():>3}  "
              f"txs {summary.network_total_transactions():>4}  "
              f"ts {summary.timestamp_ms()}")


if __name__ == "__main__":
    asyncio.run(main())
