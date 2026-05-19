# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    address = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        address, client)
    coins = await client.coins(address)
    if len(coins.data) == 0:
        raise Exception("address has no coins after faucet request")
    object_id = coins.data[0].id()

    obj = await client.object(object_id)
    if obj is None:
        raise Exception("missing object")

    print("Object ID:", obj.object_id().to_hex())
    print("Version:", obj.version())
    print("Previous transaction:", obj.previous_transaction().to_base58())
    print("Owner:", obj.owner())
    print("Storage rebate:", obj.storage_rebate())
    print("Type:", obj.object_type())
    print("BCS bytes:", hex_encode(obj.as_struct().contents))


if __name__ == "__main__":
    asyncio.run(main())
