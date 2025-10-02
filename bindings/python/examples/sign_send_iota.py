# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    try:
        # Amount to send in nanos
        amount = 1000
        recipient_address = Address.from_hex(
            "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
        )

        private_key = Ed25519PrivateKey(b'\x00' * 32)
        public_key = private_key.public_key()
        sender_address = public_key.derive_address()
        print(f"Sender address: {sender_address.to_hex()}")

        # Request funds from faucet
        faucet = FaucetClient.new_local()
        await faucet.request_and_wait(sender_address)

        client = GraphQlClient.new_localhost()
        # Get coins for the sender address
        coins_page = await client.coins(sender_address, None, None)
        if not coins_page.data:
            raise Exception("No coins found")
        gas_coin = coins_page.data[0]

        builder = await TransactionBuilder.init(sender_address, client)

        # Split the amount from the gas coin
        builder.split_coins(gas_coin.id(), [amount], ["coin1"])

        # Transfer the split coin
        builder.transfer_objects(recipient_address, [PtbArgument.res("coin1")])

        builder.gas(gas_coin.id()).gas_budget(50000000)
        gas_price = await client.reference_gas_price(None)
        if gas_price is None:
            raise Exception("Failed to get gas price")
        builder.gas_price(gas_price)

        txn = await builder.finish()

        dry_run_result = await client.dry_run_tx(txn, False)
        if dry_run_result.error is not None:
            raise Exception(f"Dry run failed: {dry_run_result.error}")

        signature = private_key.try_sign_simple(txn.signing_digest())
        user_signature = UserSignature.new_simple(signature)

        effects = await client.execute_tx([user_signature], txn)
        if effects is None:
            raise Exception("Transaction execution failed")
        print(f"Digest: {hex_encode(effects.digest().to_bytes())}")
        print(f"Transaction status: {effects.as_v1().status}")
        print(f"Effects: {effects.as_v1()}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
