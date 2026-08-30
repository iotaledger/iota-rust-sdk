# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    tx_bytes_base64 = "AAABACAAAKSYS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAEBAQABAADaGCDt9pPuMrVymQe5suyOZJgO6MAIwX6Jz7Tl7NchUQHclW3om5FOan+9g8rr78jskb4SB2Z+pVdjhjkaqCRJzPC6fSAAAAAAILFkUl8sWJyphiT+5+p5Rev6nLCp6DDtMQTNwLSMcOHw2hgg7faT7jK1cpkHubLsjmSYDujACMF+ic+05ezXIVHoAwAAAAAAAICEHgAAAAAAAA=="
    transaction = Transaction.from_base64(tx_bytes_base64)

    res = await client.dry_run_transaction(transaction)
    if res.error is not None:
        raise Exception(f"Dry run failed: {res.error}")

    print("Dry run was successful!")
    print(f"Dry run result: {res}")


if __name__ == "__main__":
    asyncio.run(main())
