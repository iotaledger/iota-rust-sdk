# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GrpcClient.new_testnet()

    info = await client.get_service_info()
    print("Chain ID:", info.chain_id)
    print("Epoch:", info.epoch)
    print("Checkpoint height:", info.checkpoint_height)

    gas_price = await client.get_reference_gas_price()
    print("Reference gas price:", gas_price)


if __name__ == "__main__":
    asyncio.run(main())
