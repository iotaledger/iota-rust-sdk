from lib.iota_sdk_ffi import GraphQlClient, PaginationFilter, Address, Direction, TransactionsFilter, ObjectId, EventFilter, ServiceConfig
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

    service_config=ServiceConfig(default_page_size=2,
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
                                 request_timeout_ms=0)


if __name__ == '__main__':
    asyncio.run(main())
