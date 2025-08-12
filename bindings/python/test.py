from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()
    chain_id = await client.chain_id()
    print(chain_id)

    my_address = Address.from_hex(
        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
    )

    coins = await client.coins(
        my_address,
        PaginationFilter(direction=Direction.FORWARD, cursor=None, limit=None),
    )
    for coin in coins.data:
        print(f"ID = 0x{coin.id().to_hex()} Balance = {coin.balance()}")

    balance = await client.balance(my_address)

    print(f"Total Balance = {balance}")

    filter = TransactionsFilter(
        at_checkpoint=3,
        input_object=ObjectId.from_hex(
            "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
        ),
    )

    filter = EventFilter(sender=my_address)

    txn = await client.transaction(
        TransactionDigest.from_base58("HT1wvebXV4LUisLa4aJQEyoxt1HEMqznjf5UtStmdxyM")
    )

    if txn is not None:
        for sig in txn.signatures():
            print("Scheme: ", sig.scheme(), sig.scheme().value)
        print("Sender: ", txn.transaction().sender().to_hex())

    move_struct = MoveStruct(
        struct_type=StructTag.coin(TypeTag.vector(TypeTag.u8())),
        version=1,
        contents=bytes(),
    )

    id = ObjectId.from_hex(
        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
    )
    type_origin = TypeOrigin(
        module_name=Identifier("module_name"),
        struct_name=Identifier("struct_name"),
        package=id,
    )
    upgrade_info = UpgradeInfo(upgraded_id=id, upgraded_version=43)
    id_module = IdentifierModuleMap(
        id=Identifier("some_id"), module=bytes.fromhex("48656c6c6f")
    )
    object_id_upgrade_info = ObjectIdUpgradeInfoMap(id=id, info=upgrade_info)
    move_package = MovePackage(
        id,
        version=42,
        modules=[id_module],
        type_origin_table=[type_origin],
        linkage_table=[object_id_upgrade_info],
    )


if __name__ == "__main__":
    asyncio.run(main())
