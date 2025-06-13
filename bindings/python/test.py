from lib.iota_graphql_client import Direction
from lib.iota_sdk_ffi import GraphQlClient, PaginationFilter
from lib.iota_sdk_types import address_from_hex, ObjectReference
import asyncio

async def main():
    client = GraphQlClient.new_devnet()
    chain_id = await client.chain_id()
    print(chain_id)

    my_address=address_from_hex("0xda06e01d11c8d3ef8f8e238c2f144076fdc6832378fb48b153d57027ae868b39")

    coins = await client.coins(
        my_address, 
        PaginationFilter(direction=Direction.FORWARD, cursor=None, limit=None)
    )
    my_coins = []
    for coin in coins.data():
        print(f'ID = 0x{coin.id.hex()} Balance = {coin.balance}')

    balance = await client.balance(my_address)

    print(f'Total Balance = {balance}')


if __name__ == '__main__':
    asyncio.run(main())
