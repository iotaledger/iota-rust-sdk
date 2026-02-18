// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package org.iota.androiddemo

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import iota_sdk.GraphQlClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var resultText: TextView
    private lateinit var fetchButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        resultText = findViewById(R.id.resultText)
        fetchButton = findViewById(R.id.fetchButton)

        fetchButton.setOnClickListener {
            fetchChainId()
        }
    }

    private fun fetchChainId() {
        fetchButton.isEnabled = false
        resultText.text = getString(R.string.fetching)

        lifecycleScope.launch {
            try {
                val chainId = withContext(Dispatchers.IO) {
                    val client = GraphQlClient.newDevnet()
                    client.chainId()
                }
                resultText.text = getString(R.string.chain_id_result, chainId)
            } catch (e: Throwable) {
                resultText.text = getString(R.string.error_result, e.message)
            } finally {
                fetchButton.isEnabled = true
            }
        }
    }
}
