# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio
import json

PREVIEW_LINES = 15


async def main():
    client = GraphQlClient.new_localnet()
    # The IOTA system state object owns the validator set and other dynamic
    # fields. It is available on every network including localnet.
    parent_object_id = Address.system_state()
    page = await client.dynamic_fields(parent_object_id)
    print("Page size:", len(page.data))
    if page.data:
        first = page.data[0]
        try:
            name_pretty = json.dumps(json.loads(str(first.name)), indent=2)
        except (TypeError, ValueError):
            name_pretty = str(first.name)
        print(f"First field name:\n{name_pretty}")

        # The field value can be large (e.g. the validator set on 0x5), so we
        # print only the first few lines as a preview.
        try:
            value_pretty = json.dumps(json.loads(str(first.value_as_json)),
                                      indent=2)
        except (TypeError, ValueError):
            value_pretty = str(first.value_as_json)
        lines = value_pretty.splitlines()
        preview = lines[:PREVIEW_LINES]
        truncated = len(lines) > PREVIEW_LINES
        print(f"First field value (first {PREVIEW_LINES} lines):")
        print("\n".join(preview))
        if truncated:
            print("... [truncated]")


if __name__ == "__main__":
    asyncio.run(main())
