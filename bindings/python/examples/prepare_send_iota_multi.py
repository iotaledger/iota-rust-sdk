# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *
import asyncio

async def main():
    client = GraphQlClient.new_devnet()
    sender_address = "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
    gas_coin_id = "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"

    recipients = [
        ("0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11", 1_000_000_000),
        ("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522", 2_000_000_000),
    ]

    gas_coin = await client.object(ObjectId.from_hex(gas_coin_id))
    if gas_coin is None:
        raise Exception("missing gas coin")

    builder = TransactionBuilder()
    split_amounts = [builder.input(UnresolvedInput.new_pure(amount.to_bytes(8, "little"))) for _, amount in recipients]
    recipient_addresses = [addr for addr, _ in recipients]

    split_coins_result = builder.split_coins(builder.gas(), split_amounts)

    for i, recipient in enumerate(recipient_addresses):
        coin_arg = split_coins_result.get_nested_result(i)
        recipient_arg = builder.input(UnresolvedInput.new_pure(Address.from_hex(recipient).to_bytes()))
        builder.transfer_objects([coin_arg], recipient_arg)

    builder.set_sender(Address.from_hex(sender_address))
    builder.set_gas_budget(50_000_000)
    builder.set_gas_price(await client.reference_gas_price())
    builder.add_gas_objects([UnresolvedInput.from_object(gas_coin).with_owned_kind()])
    txn = builder.finish()

    print("Signing Digest:", hex_encode(txn.signing_digest()))
    print("Txn Bytes:", base64_encode(txn.bcs_serialize()))
    
    res = await client.dry_run_tx(txn, False)

    if res.error is not None:
        raise Exception(f"Failed to send IOTA: {res.error}")

    print("Send IOTA dry run was successful!")

if __name__ == "__main__":
    asyncio.run(main())
