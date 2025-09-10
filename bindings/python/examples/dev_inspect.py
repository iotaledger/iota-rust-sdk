# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

import asyncio
from lib.iota_sdk_ffi import *


async def main():
    try:
        client = GraphQlClient.new_devnet()

        sender_address = Address.from_hex("0x0")

        iota_names_package_address = Address.from_hex(
            "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba"
        )
        iota_names_object_id = ObjectId.from_hex(
            "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
        )
        stdlib_address = Address.from_hex("0x1")

        name = "name.iota"
        print(f"Looking up name: {name}")

        builder = TransactionBuilder()

        # Create identifiers
        iota_names_module = Identifier("iota_names")
        registry_fn = Identifier("registry")
        name_module = Identifier("name")
        new_fn = Identifier("new")
        lookup_fn = Identifier("lookup")
        option_module = Identifier("option")
        borrow_fn = Identifier("borrow")
        name_record_module = Identifier("name_record")
        target_address_fn = Identifier("target_address")

        # Create type tags
        registry_name = Identifier("Registry")
        registry_type = StructTag(
            iota_names_package_address, registry_fn, registry_name, []
        )

        name_record_name = Identifier("NameRecord")
        name_record_type = StructTag(
            iota_names_package_address, name_record_module, name_record_name, []
        )

        # 1. Get the registry
        registry_input = builder.input(
            UnresolvedInput.new_shared(iota_names_object_id, 365644877, True)
        )
        iota_names = builder.move_call(
            Function(
                package=iota_names_package_address,
                module=iota_names_module,
                function=registry_fn,
                type_args=[TypeTag.new_struct(registry_type)],
            ),
            [registry_input],
        )

        # 2. Create name from string
        # BCS encode the string: length (as varint) + UTF-8 bytes
        name_bytes = name.encode("utf-8")
        name_len = len(name_bytes)
        if name_len < 128:
            # For strings shorter than 128 bytes, length is encoded as single byte
            bcs_encoded_name = bytes([name_len]) + name_bytes
        else:
            # For longer strings, we'd need proper varint encoding
            # but for this example, the name should be short
            raise Exception("String too long for simple BCS encoding")

        name_input = builder.input(UnresolvedInput.new_pure(bcs_encoded_name))
        name_result = builder.move_call(
            Function(
                package=iota_names_package_address,
                module=name_module,
                function=new_fn,
                type_args=[],
            ),
            [name_input],
        )

        # 3. Lookup name record
        name_record_option = builder.move_call(
            Function(
                package=iota_names_package_address,
                module=registry_fn,
                function=lookup_fn,
                type_args=[],
            ),
            [iota_names, name_result],
        )

        # 4. Borrow name record from option
        name_record = builder.move_call(
            Function(
                package=stdlib_address,
                module=option_module,
                function=borrow_fn,
                type_args=[TypeTag.new_struct(name_record_type)],
            ),
            [name_record_option],
        )

        # 5. Get target address from name record
        target_address_option = builder.move_call(
            Function(
                package=iota_names_package_address,
                module=name_record_module,
                function=target_address_fn,
                type_args=[],
            ),
            [name_record],
        )

        # 6. Borrow address from option
        builder.move_call(
            Function(
                package=stdlib_address,
                module=option_module,
                function=borrow_fn,
                type_args=[TypeTag.new_address()],
            ),
            [target_address_option],
        )

        builder.set_sender(sender_address)
        builder.set_gas_budget(50000000)
        gas_price = await client.reference_gas_price()
        if gas_price is None:
            raise Exception("Missing reference gas price")
        builder.set_gas_price(gas_price)

        txn = builder.finish()

        res = await client.dry_run_tx(txn, True)

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
                    print(f"Last result is not an address type or has wrong length: {len(return_value.bcs)}")
            else:
                print("No return value in last effect")
        else:
            print("No results found")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
