from lib.iota_graphql_client import Client, Address, PaginationFilter, Direction
import asyncio

async def main():
    client = Client.new_devnet()
    chain_id = await client.chain_id()
    print(chain_id)

    coins = await client.coins(
        Address.fromhex("da06e01d11c8d3ef8f8e238c2f144076fdc6832378fb48b153d57027ae868b39"), 
        "0x2::iota::IOTA", 
        PaginationFilter(direction=Direction.FORWARD, cursor=None, limit=None)
    )
    print(coins)

if __name__ == '__main__':
    asyncio.run(main())
