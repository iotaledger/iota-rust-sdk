# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio


async def main():
    address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
    )
    faucet_client = FaucetClient.new_localnet()
    faucet_receipt = await faucet_client.request_and_wait(address)
    if faucet_receipt:
        print("Faucet receipt:")
        for coin in faucet_receipt.sent:
            print(
                f"  Coin ID: {coin.id.to_hex()}, Amount: {coin.amount}, Digest: {coin.transfer_tx_digest.to_base58()}"
            )
    else:
        print("Faucet receipt: None")


if __name__ == "__main__":
    asyncio.run(main())
