# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import sys
import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    sender = Address.zero()

    iota_names_package_address = Address.from_hex(
        "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba"
    )
    iota_names_object_id = ObjectId.from_hex(
        "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
    )
    stdlib_address = Address.std_lib()

    name = "name.iota"
    print(f"Looking up name: {name}")

    builder = TransactionBuilder(sender).with_client(client)

    # 1. Get the registry
    builder.move_call(
        iota_names_package_address,
        Identifier("iota_names"),
        Identifier("registry"),
        [PtbArgument.shared_mut(iota_names_object_id)],
        [
            TypeTag.new_struct(
                StructTag(
                    iota_names_package_address,
                    Identifier("registry"),
                    Identifier("Registry"),
                )
            )
        ],
        ["iota_names"],
    )

    # 2. Create name from string
    builder.move_call(
        iota_names_package_address,
        Identifier("name"),
        Identifier("new"),
        [PtbArgument.string(name)],
        names=["name"],
    )

    # 3. Lookup name record
    builder.move_call(
        iota_names_package_address,
        Identifier("registry"),
        Identifier("lookup"),
        [PtbArgument.res("iota_names"), PtbArgument.res("name")],
        names=["name_record_opt"],
    )

    # 4. Borrow name record from option
    builder.move_call(
        stdlib_address,
        Identifier("option"),
        Identifier("borrow"),
        [PtbArgument.res("name_record_opt")],
        [
            TypeTag.new_struct(
                StructTag(
                    iota_names_package_address,
                    Identifier("name_record"),
                    Identifier("NameRecord"),
                )
            )
        ],
        ["name_record"],
    )

    # 5. Get target address from name record
    builder.move_call(
        iota_names_package_address,
        Identifier("name_record"),
        Identifier("target_address"),
        [PtbArgument.res("name_record")],
        names=["target_address_opt"],
    )

    # 6. Borrow address from option
    builder.move_call(
        stdlib_address,
        Identifier("option"),
        Identifier("borrow"),
        [PtbArgument.res("target_address_opt")],
        [TypeTag.new_address()],
        ["target_address"],
    )

    res = await builder.dry_run(True)

    if res.error is not None:
        raise Exception(f"Failed to lookup name: {res.error}")

    # Extract the resolved address from the last result
    if len(res.results) > 0:
        last_effect = res.results[-1]
        if len(last_effect.return_values) > 0:
            return_value = last_effect.return_values[0]
            if return_value.type_tag.is_address() and len(return_value.bcs) == 32:
                resolved_address = Address.from_bytes(return_value.bcs)
                print(f"Resolved address: {resolved_address.to_hex()}")
            else:
                print(
                    f"Last result is not an address type or has wrong length: {len(return_value.bcs)}"
                )
        else:
            print("No return value in last effect")
    else:
        print("No results found")


if __name__ == "__main__":
    asyncio.run(main())
