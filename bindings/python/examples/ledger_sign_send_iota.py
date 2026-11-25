# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# Send IOTA from a Ledger device's address on a local network. Set
# LEDGER_SIMULATOR to use the Speculos emulator instead of a device.

from lib.iota_sdk import *

import asyncio
import os


async def main():
    # Amount to send in nanos
    amount = 1000
    recipient_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    if "LEDGER_SIMULATOR" in os.environ:
        ledger = Ledger.speculos("127.0.0.1", 9999)
    else:
        ledger = Ledger.native_hid()
    await ledger.open_app()
    signer = await ledger.signer("m/44'/4218'/0'/0'/0'")
    sender_address = signer.address()
    print(f"Sender address: {sender_address}")

    client = GraphQlClient.new_localnet()

    # Request funds from faucet
    await FaucetClient.new_localnet().request_and_wait_for_finalized(
        sender_address, client)

    builder = client.transaction_builder(sender_address)
    builder.send_iota(recipient_address, PtbArgument.u64(amount))

    # The builder passes the signer the coins the transaction spends, so the
    # device shows the transfer instead of asking to blind-sign
    print("Review and approve the transaction on the device")
    effects = await builder.execute(TransactionSigner.from_ledger(signer),
                                    WaitForTransaction.FINALIZED)
    print(f"Digest: {effects.digest().to_base58()}")
    print(f"Transaction status: {effects.as_v1().status()}")


if __name__ == "__main__":
    asyncio.run(main())
