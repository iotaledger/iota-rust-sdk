# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    chain_id = await client.chain_id()
    print("Chain ID:", chain_id)


if __name__ == "__main__":
    asyncio.run(main())
