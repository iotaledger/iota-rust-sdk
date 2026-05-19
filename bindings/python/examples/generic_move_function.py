# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    sender = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        sender, client)

    builder = TransactionBuilder(sender).with_client(client)

    addr1 = Address.from_hex(
        "0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")
    addr2 = Address.from_hex(
        "0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")

    builder.move_call(
        Address.framework(),
        Identifier("vec_map"),
        Identifier("from_keys_values"),
        [
            PtbArgument.address_vec([addr1, addr2]),
            PtbArgument.u64_vec([10_000_000, 20_000_000]),
        ],
        [TypeTag.new_address(), TypeTag.new_u64()],
    )

    res = await builder.dry_run()

    if res.error is not None:
        raise Exception(f"Failed to call generic Move function: {res.error}")

    print("Successfully called generic Move function!")


if __name__ == "__main__":
    asyncio.run(main())
