# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


# A signer implemented in the host language. This one wraps a local key, which
# needs nothing but the transaction, so it opts out of the objects the builder
# fetches for a signer that shows the transaction to its user, such as a
# hardware wallet.
class AsyncSigner(TransactionSignerFn):

    def __init__(self, key: Ed25519PrivateKey):
        self.key = key

    async def sign(self, transaction: Transaction):
        return TransactionSignerFnOutput(
            signature=self.key.sign_transaction(transaction))

    def uses_objects(self):
        return False

    # Never called for a signer whose `uses_objects` returns false; the
    # interface still requires it.
    async def sign_with_objects(self, transaction: Transaction, objects):
        return await self.sign(transaction)


async def main():
    amount = 1000
    recipient_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    private_key = Ed25519PrivateKey(b"\x00" * 32)
    public_key = private_key.public_key()
    sender_address = public_key.derive_address()
    print(f"Sender address: {sender_address}")

    client = GraphQlClient.new_localnet()

    # Request funds from faucet
    faucet = FaucetClient.new_localnet()
    await faucet.request_and_wait_for_finalized(sender_address, client)

    builder = client.transaction_builder(sender_address)
    builder.send_iota(recipient_address, PtbArgument.u64(amount))

    signer = TransactionSigner(AsyncSigner(private_key))
    effects = await builder.execute(signer, WaitForTransaction.FINALIZED)

    print(f"Digest: {hex_encode(effects.digest().to_bytes())}")
    print(f"Transaction status: {effects.as_v1().status()}")
    print(f"Effects: {effects.as_v1()}")


if __name__ == "__main__":
    asyncio.run(main())
