# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import asyncio

from lib.iota_sdk_ffi import *


async def main():
    client = GraphQlClient.new_localnet()
    gas_station_url = "http://0.0.0.0:9527"
    gas_station_auth_token = "test"
    keypair = Ed25519PrivateKey.generate()
    sender = keypair.public_key().derive_address()
    simple_key = SimpleKeypair.from_ed25519(keypair)

    builder = await TransactionBuilder.init(sender, client)

    builder.move_call(
        Address.from_hex("0x1"),
        Identifier("u64"),
        Identifier("sqrt"),
        [PtbArgument.u64(64)],
    )

    builder.gas_station_sponsor(
        gas_station_url, headers={"Authorization": [f"Bearer {gas_station_auth_token}"]}
    )

    res = await builder.execute(simple_key, True)

    if res is not None:
        print(res)

    print("Sponsored transaction was successful!")


if __name__ == "__main__":
    asyncio.run(main())
