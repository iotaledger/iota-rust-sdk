# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    # Amount to send in nanos
    amount = 1000
    recipient_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    private_key = Ed25519PrivateKey(b"\x00" * 32)
    sender_address = private_key.public_key().derive_address()
    print(f"Sender address: {sender_address.to_hex()}")

    # Request funds from faucet (the faucet client relies on GraphQL to await
    # finalization)
    faucet = FaucetClient.new_localnet()
    await faucet.request_and_wait_for_finalized(sender_address,
                                                GraphQlClient.new_localnet())

    client = GrpcClient.new_localnet()

    # Resolve gas and build the transaction via gRPC
    builder = TransactionBuilder(sender_address).with_grpc_client(client)
    builder.send_iota(recipient_address, PtbArgument.u64(amount))
    txn = await builder.finish()

    signature = private_key.try_sign_simple(txn.signing_digest())
    user_signature = UserSignature.new_simple(signature)
    signed_transaction = SignedTransaction(transaction=txn,
                                           signatures=[user_signature])

    executed = await client.execute_transaction(signed_transaction)

    print(f"Digest: {hex_encode(executed.digest.to_bytes())}")
    print(f"Transaction status: {executed.effects.as_v1().status}")


if __name__ == "__main__":
    asyncio.run(main())
