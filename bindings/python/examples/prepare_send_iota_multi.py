# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()
    sender = Address.from_hex(
        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
    )
    gas_coin_id = ObjectId.from_hex(
        "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
    )

    recipient1 = Address.from_hex(
        "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11"
    )
    recipient2 = Address.from_hex(
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522"
    )

    builder = await TransactionBuilder.build(sender, client)

    builder.split_coins(gas_coin_id, [1_000_000_000, 2_000_000_000], ["coin1", "coin2"])
    builder.transfer_objects(recipient1, [PtbArgument.res("coin1")])
    builder.transfer_objects(recipient2, [PtbArgument.res("coin2")])
    builder.gas(gas_coin_id).gas_budget(1000000000)

    txn = await builder.finish()

    print("Signing Digest:", hex_encode(txn.signing_digest()))
    print("Txn Bytes:", base64_encode(txn.bcs_serialize()))

    res = await builder.dry_run()

    if res.error is not None:
        raise Exception(f"Failed to send IOTA: {res.error}")

    print("Send IOTA dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
