# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import sys
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    my_address = Address.from_hex(
        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

    validators = await client.active_validators()
    if len(validators.data) == 0:
        raise Exception("no validators found")
    validator = validators.data[0]

    print("Staking to validator", validator.name or "with no name")

    builder = await TransactionBuilder(my_address).with_client(client)

    builder.stake(PtbArgument.u64(1000000000), validator.address)

    res = await builder.dry_run()
    if res.error is not None:
        raise Exception("Failed to stake:", res.error)

    print("Stake dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
