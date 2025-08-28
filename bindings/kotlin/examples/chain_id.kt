import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()
        val chainId = client.chainId()
        println("Chain ID: $chainId")

    } catch (e: Exception) {
        e.printStackTrace()
    }
}
