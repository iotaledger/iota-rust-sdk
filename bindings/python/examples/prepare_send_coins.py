# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    try:
        client = GraphQlClient.new_devnet()

        from_address = Address.from_hex(
            "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
        )
        to_address = Address.from_hex(
            "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
        )

        # This is a coin of type
        # 0x3358bea865960fea2a1c6844b6fc365f662463dd1821f619838eb2e606a53b6a::cert::CERT
        coin_id = ObjectId.from_hex(
            "0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9"
        )
        gas_coin_id = ObjectId.from_hex(
            "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
        )

        builder = await TransactionBuilder.init(from_address, client)
        builder.send_coins(
            [coin_id],
            to_address,
            50000000000,
        )
        builder.gas(gas_coin_id).gas_budget(1000000000)

        txn = await builder.finish()

        print("Signing Digest:", hex_encode(txn.signing_digest()))
        print("Txn Bytes:", base64_encode(txn.bcs_serialize()))

        res = await builder.dry_run()
        if res.error is not None:
            raise Exception("Failed to send coins:", res.error)

        print("Send coins dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
