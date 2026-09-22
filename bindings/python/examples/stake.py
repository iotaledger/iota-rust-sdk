# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    my_address = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

    validators = await client.active_validators()
    if len(validators.data) == 0:
        raise Exception("no validators found")
    validator = validators.data[0]

    print("Staking to validator", validator.name or "with no name")

    builder = client.transaction_builder(my_address)

    builder.stake(PtbArgument.u64(1000000000), validator.address)

    res = await builder.dry_run()
    if res.error is not None:
        raise Exception("Failed to stake:", res.error)

    print("Stake dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
