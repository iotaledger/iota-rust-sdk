# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    from_address = Address.from_hex(
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
    to_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    obj_ids = [
        ObjectId.from_hex(
            "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db"
        ),
        ObjectId.from_hex(
            "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc"
        ),
        ObjectId.from_hex(
            "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2"
        ),
    ]
    objs_to_transfer = []
    for obj_id in obj_ids:
        obj = await client.object(obj_id)
        if obj == None:
            raise Exception("Missing object:", obj_id)
        objs_to_transfer.append(PtbArgument.object_ref(obj.object_ref()))

    gas_coin_id = ObjectId.from_hex(
        "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")
    gas_coin = await client.object(gas_coin_id)
    if gas_coin == None:
        raise Exception("Missing gas coin:", gas_coin)
    gas_price = await client.reference_gas_price() or 100

    builder = TransactionBuilder(from_address)
    builder.transfer_objects(
        to_address,
        objs_to_transfer,
    )
    builder.gas([gas_coin.object_ref()
                ]).gas_price(gas_price).gas_budget(500000000)

    txn = builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_transaction(txn)
    if res.error is not None:
        raise Exception("Failed to transfer objects:", res.error)

    print("Transfer objects dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
