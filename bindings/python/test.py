from lib.iota_graphql_client import Direction
from lib.iota_sdk_ffi import GraphQlClient, Address, PaginationFilter, Coin, TypeTag
from lib.iota_sdk_types import StructTag, ObjectId
import asyncio

async def main():
    client = GraphQlClient.new_devnet()
    chain_id = await client.chain_id()
    print(chain_id)

    coins = await client.coins(
        Address.fromhex("da06e01d11c8d3ef8f8e238c2f144076fdc6832378fb48b153d57027ae868b39"), 
        None, 
        PaginationFilter(direction=Direction.FORWARD, cursor=None, limit=None)
    )
    for coin in coins.data():
        print(f'ID = 0x{coin.id.hex()} Balance = {coin.balance}')
    
    print(Coin(
        coin_type=TypeTag.STRUCT(StructTag(address=Address.fromhex("0000000000000000000000000000000000000000000000000000000000000002"), module="iota", name="IOTA")),
        id=ObjectId.fromhex("fe017be0c7b037fc81333d18dc408512bd1904377e24bb91648cdc268040e739"),
        balance=10000000000
    ))

if __name__ == '__main__':
    asyncio.run(main())
