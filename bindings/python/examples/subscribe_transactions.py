# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# Tail transactions as they are executed, over a GraphQL subscription.
#
# Unlike the paginated queries, a subscription never ends on its own: it is
# pulled one update at a time and stopped with `cancel`. Localnet may be idle,
# so the example asks the faucet for coins to generate a transaction, and
# cancels after a deadline so it cannot hang.

from lib.iota_sdk import *

import asyncio

DEADLINE_SECONDS = 60


async def generate_activity():
    # Give the subscription a moment to connect before generating activity,
    # otherwise the transaction lands before anyone is listening.
    await asyncio.sleep(2)
    address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
    await FaucetClient.new_localnet().request_and_wait(address)


async def main():
    client = GraphQlClient.new_localnet()
    subscription = await client.transactions_subscription(
        filter=SubscriptionTransactionFilter(
            kind=TransactionBlockKindInput.PROGRAMMABLE_TX))

    activity = asyncio.create_task(generate_activity())
    # Cancelling unblocks a pending `next`, which is what keeps the example from
    # waiting forever on a network that produces nothing.
    loop = asyncio.get_running_loop()
    watchdog = loop.call_later(DEADLINE_SECONDS, subscription.cancel)

    try:
        print("Waiting for a transaction...")
        while True:
            update = await subscription.next()
            if update is None:
                raise SystemExit(
                    f"No transaction observed within {DEADLINE_SECONDS}s")

            if update.is_TRANSACTION():
                transaction = update.transaction.transaction
                print("Digest: ", transaction.digest().to_base58())
                print("Sender: ", transaction.sender().to_hex())
                break
            else:
                # Delivery recovers on its own; items in the gap may be missed.
                print("Interrupted: ", update.message)
    finally:
        watchdog.cancel()
        activity.cancel()
        subscription.cancel()


if __name__ == "__main__":
    asyncio.run(main())
