# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# This example demonstrates how to print types as human-readable text
# with the `to_display_string()` method.

from lib.iota_sdk import *


def main():
    # A sample transaction in base64 format
    tx_bytes_base64 = "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA="

    transaction = Transaction.from_base64(tx_bytes_base64)
    print(transaction.to_display_string())

    print(transaction.gas_payment().to_display_string())


if __name__ == "__main__":
    main()
