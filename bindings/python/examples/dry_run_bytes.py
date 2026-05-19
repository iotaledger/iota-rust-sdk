# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio

# A pre-encoded programmable transaction calling `0x1::u64::max(1, 2)` with
# empty gas-payment objects. Because the bytes do not reference any on-chain
# object refs, they stay valid across networks — the dry-run endpoint fills in
# gas coins on demand.
TX_BYTES_BASE64 = "AAACAAgBAAAAAAAAAAAIAgAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA3U2NANtYXgAAgEAAAEBACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUiACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUi6AMAAAAAAAAAAAAAAAAAAAA="


async def main():
    client = GraphQlClient.new_localnet()

    transaction = Transaction.from_base64(TX_BYTES_BASE64)

    res = await client.dry_run_tx(transaction, False)
    if res.error is not None:
        raise Exception(f"Dry run failed: {res.error}")

    print("Dry run was successful!")
    print(f"Dry run result: {res}")


if __name__ == "__main__":
    asyncio.run(main())
