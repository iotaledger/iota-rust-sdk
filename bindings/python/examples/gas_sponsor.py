# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    try:
        client = GraphQlClient.new_devnet()

        sender = Address.from_hex(
            "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
        )
        sponsor = Address.from_hex(
            "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
        )

        builder = await TransactionBuilder.init(sender, client)

        package_addr = Address.std_lib()
        module_name = Identifier("u8")
        function_name = Identifier("max")

        builder.move_call(
            package_addr,
            module_name,
            function_name,
            [PtbArgument.u8(0), PtbArgument.u8(1)],
        )

        gas_obj_id = ObjectId.from_hex(
            "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
        )
        builder.gas(gas_obj_id).sponsor(sponsor)

        txn = await builder.finish()

        print("Signing Digest:", hex_encode(txn.signing_digest()))
        print("Txn Bytes:", base64_encode(txn.to_bcs()))

        res = await client.dry_run_tx(txn)
        if res.error is not None:
            raise Exception("Failed to send gas sponsor tx:", res.error)

        print("Gas sponsor tx dry run was successful!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
