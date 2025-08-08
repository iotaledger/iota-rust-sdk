from lib.iota_sdk_ffi import GraphQlClient, PaginationFilter, Address, Direction, TransactionsFilter, ObjectId, EventFilter, MoveStruct, MovePackage, TypeOrigin, UpgradeInfo, IdentifierModuleMap, ObjectIdUpgradeInfoMap

import asyncio

async def main():
    client = GraphQlClient.new_devnet()
    chain_id = await client.chain_id()
    print(chain_id)
    
    my_address=Address.from_hex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f")

    coins = await client.coins(
        my_address, 
        PaginationFilter(direction=Direction.FORWARD, cursor=None, limit=None)
    )
    for coin in coins.data:
        print(f'ID = 0x{coin.id().to_hex()} Balance = {coin.balance()}')

    balance = await client.balance(my_address)

    print(f'Total Balance = {balance}')

    filter=TransactionsFilter(at_checkpoint=3, input_object=ObjectId.from_hex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"))

    filter=EventFilter(sender=my_address)

    # TODO depends on StructTag
    # move_struct = MoveStruct(struct_tag, version, contents)

    id = ObjectId.from_hex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f")
    move_package = MovePackage(id, version=42, modules=[], type_origin_table=[], linkage_table=[])
    type_origin = TypeOrigin(module_name="module_name", struct_name="struct_name", package=id)
    upgrade_info = UpgradeInfo(upgraded_id=id, upgraded_version=43)
    id_module = IdentifierModuleMap(id="some_id", module=bytes.fromhex("48656c6c6f"))
    object_id_upgrade_info = ObjectIdUpgradeInfoMap(id=id, info=upgrade_info)

if __name__ == '__main__':
    asyncio.run(main())
