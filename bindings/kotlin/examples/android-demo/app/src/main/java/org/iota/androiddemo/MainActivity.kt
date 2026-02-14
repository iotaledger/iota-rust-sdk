package org.iota.androiddemo

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import iota_sdk.GraphQlClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val status = findViewById<TextView>(R.id.status)
        status.text = "Calling IOTA devnet..."

        CoroutineScope(Dispatchers.IO).launch {
            val text = runCatching {
                val client = GraphQlClient.newDevnet()
                "Chain ID: ${client.chainId()}"
            }.getOrElse { "Error: ${it.message}" }

            withContext(Dispatchers.Main) {
                status.text = text
            }
        }
    }
}
