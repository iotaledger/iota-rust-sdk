# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()
    sender = Address.from_hex(
        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
    )
    coin_id = ObjectId.from_hex(
        "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
    )

    recipients = [
        (
            "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11",
            1_000_000_000,
        ),
        (
            "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522",
            2_000_000_000,
        ),
    ]

    amounts = [PtbArgument.u64(r[1]) for r in recipients]
    labels = [f"coin{i}" for i in range(len(recipients))]

    builder = await ClientTransactionBuilder.init(sender, client)

    builder.split_coins(PtbArgument.object_id(coin_id), amounts, labels)
    for i, r in enumerate(recipients):
        builder.transfer_objects(Address.from_hex(r[0]), [PtbArgument.res(labels[i])])

    txn = await builder.finish()

    print("Signing Digest:", txn.signing_digest_hex())
    print("Txn Bytes:", txn.to_base64())

    res = await client.dry_run_tx(txn)

    if res.error is not None:
        raise Exception(f"Failed to send IOTA: {res.error}")

    print("Send IOTA dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
