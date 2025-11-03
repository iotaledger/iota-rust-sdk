# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import sys
import asyncio

async def main():
    try:
        client = GraphQlClient.new_devnet()

        staked_iotas = await client.objects(
            filter=ObjectFilter(type_tag="0x3::staking_pool::StakedIota")
        )

        if len(staked_iotas.data) == 0:
            print("No StakedIota objects found")
        else:
            print("StakedIota object IDs:")
            for staked_iota in staked_iotas.data:
                print(staked_iota.object_id().to_hex())

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
