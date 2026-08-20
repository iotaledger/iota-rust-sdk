# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()
    gas_station_url = "http://0.0.0.0:9527"
    gas_station_auth_token = "test"
    keypair = Ed25519PrivateKey.random()
    sender = keypair.public_key().derive_address()
    signer = TransactionSigner.from_ed25519(keypair)

    builder = client.transaction_builder(sender)

    builder.move_call(
        Address.std(),
        Identifier("u64"),
        Identifier("sqrt"),
        [PtbArgument.u64(64)],
    )

    builder.gas_station_sponsor(
        gas_station_url,
        headers={"Authorization": [f"Bearer {gas_station_auth_token}"]})

    res = await builder.execute(signer)

    print(res)

    print("Sponsored transaction was successful!")


if __name__ == "__main__":
    asyncio.run(main())
