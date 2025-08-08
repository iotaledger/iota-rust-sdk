from lib.iota_sdk_ffi import GraphQlClient, PaginationFilter, Address, Direction, TransactionsFilter, ObjectId, EventFilter, TransactionDigest
import asyncio

async def main():
    client = GraphQlClient.new_devnet()
    chain_id = await client.chain_id()
    print(chain_id)
    
    my_address = Address.from_hex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f")

    coins = await client.coins(
        my_address, 
        PaginationFilter(direction=Direction.FORWARD, cursor=None, limit=None)
    )
    for coin in coins.data():
        print(f'ID = 0x{coin.id().to_hex()} Balance = {coin.balance()}')

    balance = await client.balance(my_address)

    print(f'Total Balance = {balance}')

    filter = TransactionsFilter(at_checkpoint=3, input_object=ObjectId.from_hex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"))

    filter = EventFilter(sender=my_address)

    txn = await client.transaction(TransactionDigest.from_base58("HT1wvebXV4LUisLa4aJQEyoxt1HEMqznjf5UtStmdxyM"))

    if txn is not None:
        for sig in txn.signatures():
            print("Scheme: ", sig.scheme(), sig.scheme().value)
        print("Sender: ", txn.transaction().sender().to_hex())


if __name__ == '__main__':
    asyncio.run(main())
