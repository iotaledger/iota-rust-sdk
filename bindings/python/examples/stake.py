# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    my_address = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        my_address, client)

    validators = await client.active_validators()
    if len(validators.data) == 0:
        raise Exception("no validators found")
    validator = validators.data[0]

    print("Staking to validator", validator.name or "with no name")

    builder = TransactionBuilder(my_address).with_client(client)

    builder.stake(PtbArgument.u64(1000000000), validator.address)

    res = await builder.dry_run(False)
    if res.error is not None:
        raise Exception("Failed to stake:", res.error)

    print("Stake dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
