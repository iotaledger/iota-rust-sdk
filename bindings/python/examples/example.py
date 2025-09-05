from lib.iota_sdk_ffi import *

import asyncio


async def main():
    client = GraphQlClient.new_devnet()

    my_address = Address.from_hex(
        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
    )

    coins = await client.coins(my_address)
    for coin in coins.data:
        print(f"ID = {coin.id().to_hex()} Balance = {coin.balance()}")

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
        Digest.from_base58("HT1wvebXV4LUisLa4aJQEyoxt1HEMqznjf5UtStmdxyM")
    )

    if txn is not None:
        for sig in txn.signatures:
            print("Scheme: ", sig.scheme(), sig.scheme().value)
        print("Sender: ", txn.transaction.sender().to_hex())

    service_config = ServiceConfig(
        default_page_size=2,
        enabled_features=[],
        max_move_value_depth=0,
        max_output_nodes=0,
        max_page_size=0,
        max_query_depth=0,
        max_query_nodes=0,
        max_query_payload_size=0,
        max_type_argument_depth=0,
        max_type_argument_width=0,
        max_type_nodes=0,
        mutation_timeout_ms=0,
        request_timeout_ms=0,
    )

    coin_metadata = CoinMetadata(
        address=ObjectId.from_hex(
            "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
        ),
        decimals=2,
        description="test",
        icon_url=None,
        name="test",
        symbol=None,
        supply="1000",
        version=0,
    )

    move_struct = MoveStruct(
        struct_type=StructTag.coin(TypeTag.new_vector(TypeTag.new_u8())),
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
    move_package = MovePackage(
        id,
        version=42,
        modules={Identifier("some_id"): bytes.fromhex("48656c6c6f")},
        type_origin_table=[type_origin],
        linkage_table={id: upgrade_info},
    )

    builder = TransactionBuilder()
    framework_addr = Address.from_hex(
        "0x0000000000000000000000000000000000000000000000000000000000000002"
    )
    builder.move_call(
        Function(
            package=framework_addr,
            module=Identifier("coin"),
            function=Identifier("value"),
            type_args=[
                TypeTag.new_struct(
                    StructTag(
                        framework_addr, Identifier("iota"), Identifier("IOTA"), []
                    )
                )
            ],
        ),
        [Argument.new_input(0)],
    )
    builder.set_sender(my_address)
    builder.set_gas_budget(50000000)
    builder.set_gas_price(await client.reference_gas_price() or 100)
    coin_0 = await client.object(coins.data[0].id())
    if coin_0 is None:
        raise InternalError
    coin_1 = await client.object(coins.data[1].id())
    if coin_1 is None:
        raise InternalError
    builder.input(UnresolvedInput.from_object(coin_0).with_owned_kind())
    builder.add_gas_objects([UnresolvedInput.from_object(coin_1).with_owned_kind()])
    txn = builder.finish()

    res = await client.dry_run_tx(txn)
    if res.error is not None:
        print(res.error)
    elif res.effects is not None:
        print(res.effects.as_v1())


if __name__ == "__main__":
    asyncio.run(main())
