# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# This example demonstrates how to convert a Transaction to and from JSON.
# A similar roundtrip can be done for other types as well.

from lib.iota_sdk import *


def main():
    # A sample transaction in base64 format
    tx_bytes_base64 = "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA="

    # Parse the transaction from base64
    transaction = Transaction.from_base64(tx_bytes_base64)

    # Convert the transaction to JSON
    json = transaction.to_json()
    print(f"Transaction as JSON:\n{json}")

    # Convert the JSON back to a transaction
    parsed_transaction = Transaction.from_json(json)
    print(f"Parsed transaction back from JSON: {parsed_transaction}")


if __name__ == "__main__":
    main()
