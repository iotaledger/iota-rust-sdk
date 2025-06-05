from lib.client import Client, uniffi_set_event_loop
import asyncio

uniffi_set_event_loop(asyncio.get_running_loop())

async def main():
    client = Client.new_devnet()
    chain_id = await client.chain_id()
    print(chain_id)

if __name__ == '__main__':
    asyncio.run(main())
