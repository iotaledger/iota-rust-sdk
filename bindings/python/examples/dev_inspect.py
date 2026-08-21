# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_testnet()

    sender = Address.zero()

    iota_names_package_address = Address.from_hex(
        "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea")
    iota_names_object_id = ObjectId.from_hex(
        "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")
    std_address = Address.std()

    name = "name.iota"
    print(f"Looking up name: {name}")

    builder = client.transaction_builder(sender)

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
                ))
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
        [PtbArgument.assigned("iota_names"),
         PtbArgument.assigned("name")],
        names=["name_record_opt"],
    )

    # 4. Borrow name record from option
    builder.move_call(
        std_address,
        Identifier("option"),
        Identifier("borrow"),
        [PtbArgument.assigned("name_record_opt")],
        [
            TypeTag.new_struct(
                StructTag(
                    iota_names_package_address,
                    Identifier("name_record"),
                    Identifier("NameRecord"),
                ))
        ],
        ["name_record"],
    )

    # 5. Get target address from name record
    builder.move_call(
        iota_names_package_address,
        Identifier("name_record"),
        Identifier("target_address"),
        [PtbArgument.assigned("name_record")],
        names=["target_address_opt"],
    )

    # 6. Borrow address from option
    builder.move_call(
        std_address,
        Identifier("option"),
        Identifier("borrow"),
        [PtbArgument.assigned("target_address_opt")],
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
            if return_value.type_tag.is_address() and len(
                    return_value.bcs) == 32:
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
