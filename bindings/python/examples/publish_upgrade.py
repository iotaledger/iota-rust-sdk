# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# This example allows you to publish any Move package by compiling it
# first using the `iota` binary. For demonstration purposes this example
# immediately upgrades the package after publishing it.
#
# ```bash
# cd /path/to/your/move/package
# export COMPILED_PACKAGE=$(iota move build --dump-bytecode-as-base64)
# ```
#
# ```fish
# cd /path/to/your/move/package
# set -x COMPILED_PACKAGE (iota move build --dump-bytecode-as-base64)
# ```
#
# With this example it is necessary to run a localnet:
#
# ```sh
# iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis
# ```

from lib.iota_sdk import *

import asyncio
import os


async def main():
    # Read and parse the compiled package, or use the default package
    package_data_json = os.getenv("COMPILED_PACKAGE")
    if package_data_json is None:
        print("No compiled package found in env var. Using default.")
        package_data_json = PRECOMPILED_PACKAGE
    else:
        print("Using custom Move package found in env var.")

    package_data = MovePackageData.from_json(package_data_json)
    modules = package_data.modules()
    print(f"Modules: {len(modules)}")
    dependencies = package_data.dependencies()
    print(f"Dependencies: {len(dependencies)}")
    digest = package_data.digest()
    print(f"Digest: {digest.to_base58()}")

    # Create a random private key to derive a sender address and for signing
    private_key = Ed25519PrivateKey.random()
    sender = private_key.public_key().derive_address()
    print(f"Sender: {sender.to_hex()}")

    client = GraphQlClient.new_localnet()

    # Fund the sender address for gas payment
    faucet = FaucetClient.new_localnet()
    faucet_receipt = await faucet.request_and_wait_for_finalized(sender, client)
    if faucet_receipt is None:
        raise Exception("Failed to request coins from faucet")

    # Build the `publish` PTB
    builder = client.transaction_builder(sender)
    # Publish the package and receive the upgrade cap in return
    builder.publish_package(package_data, "upgrade_cap")
    # Transfer the upgrade cap to the sender address
    builder.transfer_objects(sender, [PtbArgument.assigned("upgrade_cap")])
    tx = await builder.finish()

    # Perform a dry-run first to check if everything is correct
    print("> Publishing package (dry run):")
    result = await client.dry_run_tx(tx, False)
    if result.error is not None:
        raise Exception(f"Dry run failed: {result.error}")
    if result.effects is None:
        raise Exception("Dry run failed: no effects")
    print("Success")

    # Sign and execute the transaction (publish the package)
    print("> Publishing package:")
    sig = private_key.sign_transaction(tx)
    effects = await client.execute_tx([sig], tx, WaitForTx.FINALIZED)
    print("Success")

    # Resolve UpgradeCap and PackageId via the client
    upgrade_cap = None
    package_id = None
    for changed_obj in effects.as_v1().changed_objects():
        if changed_obj.output_state.is_object_write():
            object_id = changed_obj.object_id
            obj = await client.object(object_id, None)
            if obj is None:
                raise Exception(f"Missing object {object_id.to_hex()}")
            if obj.as_struct().struct_type == StructTag.new_upgrade_cap():
                print(f"UpgradeCap: {object_id.to_hex()}")
                print(
                    f"UpgradeCapOwner: {changed_obj.output_state.owner.as_address().to_hex()}"
                )
                upgrade_cap = object_id

        elif changed_obj.output_state.is_package_write():
            package_id = changed_obj.object_id
            print(f"Package ID: {package_id.to_hex()}")
            version = changed_obj.output_state.version
            print(f"Package version: {version}")

    if upgrade_cap is None:
        raise Exception("Missing upgrade cap")
    if package_id is None:
        raise Exception("Missing package id")

    # Build the `upgrade` PTB
    builder = client.transaction_builder(sender)

    # Authorize the upgrade by providing the upgrade cap object id to receive an upgrade
    # ticket
    builder.move_call(
        Address.framework(),
        Identifier("package"),
        Identifier("authorize_upgrade"),
        [
            PtbArgument.object_id(upgrade_cap),
            PtbArgument.u8(UpgradePolicy.compatible().as_u8()),
            PtbArgument.u8_vec(digest.to_bytes()),
        ],
        names=["upgrade_ticket"],
    )

    # Upgrade the package to receive an upgrade receipt
    builder.upgrade(
        package_id,
        package_data,
        PtbArgument.assigned("upgrade_ticket"),
        "upgrade_receipt",
    )

    # Commit the upgrade using the receipt
    builder.move_call(
        Address.framework(),
        Identifier("package"),
        Identifier("commit_upgrade"),
        [
            PtbArgument.object_id(upgrade_cap),
            PtbArgument.assigned("upgrade_receipt")
        ],
    )

    tx = await builder.finish()

    # Perform a dry-run first to check if everything is correct
    print("> Upgrading package (dry run):")
    result = await client.dry_run_tx(tx, False)
    if result.error is not None:
        raise Exception(f"Dry run failed: {result.error}")
    if result.effects is None:
        raise Exception("Dry run failed: no effects")
    print("Success")

    # Sign and execute the transaction (upgrade the package)
    print("> Upgrading package:")
    sig = private_key.sign_transaction(tx)
    effects = await client.execute_tx([sig], tx)
    print("Success")

    # Print the new package version (should now be 2)
    for changed_obj in effects.as_v1().changed_objects():
        if changed_obj.output_state.is_package_write():
            print(f"New Package ID: {changed_obj.object_id.to_hex()}")
            print(f"New Package version: {changed_obj.output_state.version}")


PRECOMPILED_PACKAGE = '{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}'

if __name__ == "__main__":
    asyncio.run(main())
