# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()
    account_id = await setup_account(client)
    from_address = account_id.to_address()
    to_address = Address.from_hex(
        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

    # Fund the sender address for gas payment
    faucet = FaucetClient.new_localnet()
    faucet_receipt = await faucet.request_and_wait_for_finalized(
        from_address, client)
    if faucet_receipt is None:
        raise Exception("Failed to request coins from faucet")

    builder = TransactionBuilder(from_address).with_client(client)
    builder.send_iota(to_address, PtbArgument.u64(5000000000))

    move_authenticator = await MoveAuthenticatorBuilder(
        account_id,
        [PtbArgument.string("hello"),
         PtbArgument.shared(ObjectId.clock())],
        [],
    ).finish(client)

    signer = TransactionSigner.from_move_authenticator(move_authenticator)
    effects = await builder.execute(signer, WaitForTx.FINALIZED)

    print(f"Sending IOTA via abstract account: {effects.as_v1().status}")


async def setup_account(client: GraphQlClient) -> ObjectId:
    # Parse the precompiled move package
    package_data = MovePackageData.from_json(PRECOMPILED_PACKAGE)

    # Create a random private key to derive a sender address
    private_key = Ed25519PrivateKey.generate()
    sender = private_key.public_key().derive_address()

    # Fund the sender address for gas payment
    faucet = FaucetClient.new_localnet()
    faucet_receipt = await faucet.request_and_wait_for_finalized(sender, client)
    if faucet_receipt is None:
        raise Exception("Failed to request coins from faucet")

    # Build the `publish` PTB
    builder = TransactionBuilder(sender).with_client(client)
    # Publish the package and receive the upgrade cap
    builder.publish(package_data, "upgrade_cap")
    # Transfer the upgrade cap to the sender address
    builder.transfer_objects(sender, [PtbArgument.assigned("upgrade_cap")])

    # Sign and execute the transaction (publish the package)
    signer = TransactionSigner.from_ed25519(private_key)
    effects = await builder.execute(signer, WaitForTx.FINALIZED)

    print(f"Publishing package: {effects.as_v1().status}\n")

    # Get package, package metadata and account IDs from the effects
    package_id = None
    package_metadata_id = None
    account_id = None

    for changed_obj in effects.as_v1().changed_objects:
        if changed_obj.output_state.is_package_write():
            package_id = changed_obj.object_id
        elif changed_obj.output_state.is_object_write():
            object_id = changed_obj.object_id
            obj = await client.object(object_id, None)

            if obj is not None:
                type_name = obj.as_struct().struct_type.name().as_str()
                if type_name == "PackageMetadataV1":
                    package_metadata_id = object_id
                if type_name == "Account":
                    account_id = object_id

    if package_id is None:
        raise Exception("Missing package id")
    if package_metadata_id is None:
        raise Exception("Missing package metadata id")
    if account_id is None:
        raise Exception("Missing account id")

    print(f"Package ID: {package_id.to_hex()}")
    print(f"PackageMetadataV1 ID: {package_metadata_id.to_hex()}")
    print(f"Account ID: {account_id.to_hex()}\n")

    # Build the `link_auth` PTB
    builder = TransactionBuilder(sender).with_client(client)
    builder.move_call(
        package_id.to_address(),
        Identifier("account"),
        Identifier("link_auth"),
        [
            PtbArgument.shared_mut(account_id),
            PtbArgument.object_id(package_metadata_id),
            PtbArgument.string("account"),
            PtbArgument.string("authenticate"),
        ],
    )

    # Sign and execute the transaction (link the authenticator)
    effects = await builder.execute(signer, WaitForTx.FINALIZED)

    print(f"Linking account to authenticate method: {effects.as_v1().status}\n")

    return account_id


# The package below, compiled and exported using `iota move build --dump-bytecode-as-base64`
PRECOMPILED_PACKAGE = '{"modules":["oRzrCwYAAAALAQAUAhQmAzorBGUGBWtPB7oBwAII+gNgBtoECRDjBCoKjQULDJgFQgAJAgkCCwINAg4CFgIXAhoCGwEKAAEMAAAAAgACAgIAAwMHAQgBBAQIAAUIBAAGBQgACAcCAAkGBwAAEwABAAAUAgEAAAwDAQABDwsBAQgDEAkKAQgFFQQFAAcYBwEBDAkZDA0ABgYEBgMGAggBBwgHAAQIAAYIBggICAgFBggACAgGCAQGCAIGCAcBBwgHAQgFAQgAAQkAAQsDAQgAAwYIBggICAgBCwMBCQACCQALAwEJAAEKAgEICAdBQ0NPVU5UB0FjY291bnQLQXV0aENvbnRleHQaQXV0aGVudGljYXRvckZ1bmN0aW9uUmVmVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlFmF1dGhlbnRpY2F0b3JfZnVuY3Rpb24FY2xvY2sRY3JlYXRlX2FjY291bnRfdjEbY3JlYXRlX2F1dGhfZnVuY3Rpb25fcmVmX3YxC2R1bW15X2ZpZWxkAmlkBGluaXQJbGlua19hdXRoA25ldwZvYmplY3QQcGFja2FnZV9tZXRhZGF0YRNwdWJsaWNfc2hhcmVfb2JqZWN0BnN0cmluZwh0cmFuc2Zlcgp0eF9jb250ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCgIGBWhlbGxvDmlvdGE6Om1ldGFkYXRhGgEAAAAAAAAAEQEMYXV0aGVudGljYXRlAQABAAIBEggFAQIBEQEAAAAAAQULAREFEgA4AAIBAQAACAkLAQsCCwM4AQwECwALBDgCAgIBAAABCQsBBwARByEEBgUIBgAAAAAAAAAAJwIA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[236,68,86,252,91,28,224,206,146,112,120,93,47,52,14,168,169,132,252,75,45,104,10,116,171,91,155,100,66,111,66,147]}'

if __name__ == "__main__":
    asyncio.run(main())

# pylint: disable=unused-variable
PACKAGE = r'''
module account::account;
...
'''
