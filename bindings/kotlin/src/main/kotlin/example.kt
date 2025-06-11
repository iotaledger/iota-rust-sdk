import kotlinx.coroutines.runBlocking
import uniffi.iota_sdk_ffi.GraphQlClient

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()
        val chainId = client.chainId()
        println("Chain ID: $chainId")

        val myAddress =
                uniffi.iota_sdk_ffi.Address.fromHex(
                        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
                )

        val coins =
                client.coins(
                        myAddress,
                        uniffi.iota_sdk_ffi.PaginationFilter(
                                direction = uniffi.iota_sdk_ffi.Direction.FORWARD,
                                cursor = null,
                                limit = null
                        ),
                        null // coinType
                )
        for (coin in coins.data) {
            println("ID = 0x${coin.id().toHex()} Balance = ${coin.balance()}")
        }

        // Replicate: balance = await client.balance(my_address)
        val balance = client.balance(myAddress, null)
        println("Total Balance = $balance")

        val _txFilter =
                uniffi.iota_sdk_ffi.TransactionsFilter(
                        atCheckpoint = 3UL,
                        inputObject =
                                uniffi.iota_sdk_ffi.ObjectId.fromHex(
                                        "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f"
                                ),
                        // ...other fields as needed
                        )

        val _eventFilter =
                uniffi.iota_sdk_ffi.EventFilter(
                        sender = myAddress
                        // ...other fields as needed
                        )
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
