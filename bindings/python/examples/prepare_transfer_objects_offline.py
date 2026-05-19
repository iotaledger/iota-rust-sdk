# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    from_address = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
    to_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    # Prefetch object refs and gas price online so the rest of the example can
    # be assembled offline.
    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        from_address, client)
    owned = await client.objects(
        ObjectFilter(owner=from_address,
                     type_tag="0x2::coin::Coin<0x2::iota::IOTA>"))
    if len(owned.data) < 4:
        raise Exception(
            "sender does not own at least 4 coins (1 for gas + 3 to transfer)")
    gas_coin_ref = owned.data[0].object_ref()
    objs_to_transfer = [
        PtbArgument.object_ref(obj.object_ref()) for obj in owned.data[1:4]
    ]
    gas_price = await client.reference_gas_price() or 100

    # From here on, no further network calls are made; the transaction is
    # assembled entirely from the prefetched object refs.
    builder = TransactionBuilder(from_address)
    builder.transfer_objects(
        to_address,
        objs_to_transfer,
    )
    builder.gas([gas_coin_ref]).gas_price(gas_price).gas_budget(500000000)

    txn = builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_tx(txn, False)
    if res.error is not None:
        raise Exception("Failed to transfer objects:", res.error)

    print("Transfer objects dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
