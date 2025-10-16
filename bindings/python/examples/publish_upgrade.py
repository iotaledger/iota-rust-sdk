# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk_ffi import *

import asyncio
import json
import base64

# Compiled `first_package` example
SERIALIZED_FIRST_PACKAGE = '{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}'


async def main():
    try:
        # Parse the compiled `first_package` example from the monorepo created with
        # `iota move build --dump-bytecode-as-base64`
        data = json.loads(SERIALIZED_FIRST_PACKAGE)
        modules = [base64.b64decode(module) for module in data["modules"]]
        dependencies = [ObjectId.from_hex(dep) for dep in data["dependencies"]]
        compiled_package_digest = bytes(data["digest"])
        print(f"Compiled Package Digest: {compiled_package_digest.hex()}")

        # Create a random private key to derive a sender address and for signing
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        sender = public_key.derive_address()
        print(f"Sender: {sender.to_hex()}")

        # Fund the sender address for gas payment
        faucet = FaucetClient.new_localnet()
        faucet_receipt = await faucet.request_and_wait(sender)
        if faucet_receipt is None:
            raise Exception("Failed to request coins from faucet")
        print(f"Available Balance: {sum(coin.amount for coin in faucet_receipt.sent)}")

        client = GraphQlClient.new_localnet()

        # Build the `publish` PTB, that consists of 2 steps
        builder = await TransactionBuilder.init(sender, client)

        # 1. Create the upgrade cap
        builder.publish(modules, dependencies, "upgrade_cap")

        # 2. Transfer the upgrade cap to the sender address
        builder.transfer_objects(sender, [PtbArgument.res("upgrade_cap")])

        # Finalize the PTB
        tx = await builder.finish()

        # Perform a dry-run to check if everything is fine
        result = await client.dry_run_tx(tx, False)
        if result.error is not None:
            raise Exception(f"Dry run failed: {result.error}")
        if result.effects is None:
            raise Exception("Dry run failed: no effects")
        print(f"Effects status (dry run): {result.effects.as_v1().status}")

        # Sign and execute the transaction (publish the package)
        print("Publishing package")
        signature = private_key.try_sign_simple(tx.signing_digest())
        user_signature = UserSignature.new_simple(signature)
        effects = await client.execute_tx([user_signature], tx)
        if effects is None:
            raise Exception("Transaction failed: no effects")
        print(f"Effects status (publish): {effects.as_v1().status}")

        # Wait some time for the indexer to process the tx
        await asyncio.sleep(3)

        # Resolve UpgradeCap and PackageId via the client
        upgrade_cap = None
        package_id = None

        for changed_obj in effects.as_v1().changed_objects:
            if hasattr(changed_obj.output_state, 'owner'):
                # ObjectWrite
                object_id = changed_obj.object_id
                obj = await client.object(object_id, None)
                if obj is None:
                    raise Exception(f"Missing object {object_id.to_hex()}")
                upgrade_cap_type = StructTag(Address.framework(), Identifier("package"), Identifier("UpgradeCap"))
                if str(obj.as_struct().struct_type) == str(upgrade_cap_type):
                    upgrade_cap = object_id
            elif hasattr(changed_obj.output_state, 'version'):
                # PackageWrite
                pkg_id = changed_obj.object_id
                package_id = pkg_id

        if upgrade_cap is None:
            raise Exception("Missing upgrade cap")
        if package_id is None:
            raise Exception("Missing package id")

        # Build the `upgrade` PTB, that consists of 3 steps
        builder = await TransactionBuilder.init(sender, client)

        upgrade_cap_arg = PtbArgument.object_id(upgrade_cap)
        upgrade_policy_arg = PtbArgument.u8(0)
        compiled_package_digest_arg = PtbArgument.u8_vec(compiled_package_digest)

        # 1. Create the upgrade ticket
        builder.move_call(
            Address.framework(),
            Identifier("package"),
            Identifier("authorize_upgrade"),
            [upgrade_cap_arg, upgrade_policy_arg, compiled_package_digest_arg],
            names=["upgrade_ticket"]
        )

        # 2. Get the upgrade receipt
        builder.upgrade(modules, dependencies, package_id, PtbArgument.res("upgrade_ticket"), "upgrade_receipt")

        # 3. Finalize the upgrade
        builder.move_call(
            Address.framework(),
            Identifier("package"),
            Identifier("commit_upgrade"),
            [upgrade_cap_arg, PtbArgument.res("upgrade_receipt")]
        )

        # Finalize the PTB
        tx = await builder.finish()

        # Perform a dry-run to check if everything is fine
        result = await client.dry_run_tx(tx, False)
        if result.error is not None:
            raise Exception(f"Dry run failed: {result.error}")
        if result.effects is None:
            raise Exception("Dry run failed: no effects")
        print(f"Effects status (dry run): {result.effects.as_v1().status}")

        # Sign and execute the transaction (upgrade the package)
        print("Upgrading package")
        signature = private_key.try_sign_simple(tx.signing_digest())
        user_signature = UserSignature.new_simple(signature)
        effects = await client.execute_tx([user_signature], tx)
        if effects is None:
            raise Exception("Transaction failed: no effects")
        print(f"Effects status (upgrade): {effects.as_v1().status}")

        # Wait some time for the indexer to process the tx
        await asyncio.sleep(3)

        # Print the new package version (should now be 2)
        for changed_obj in effects.as_v1().changed_objects:
            if hasattr(changed_obj.output_state, 'version'):
                pkg_id = changed_obj.object_id
                print(f"PackageId: {pkg_id.to_hex()}")
                print(f"Package version: {changed_obj.output_state.version}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
