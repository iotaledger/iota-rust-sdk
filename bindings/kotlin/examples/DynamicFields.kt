// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()
        // The IOTA system state object owns the validator set and other dynamic
        // fields. It is available on every network including localnet.
        val parentObjectId = iota_sdk.Address.systemState()
        val page = client.dynamicFields(parentObjectId)
        println("Page size: ${page.data.size}")
        val first = page.data.firstOrNull()
        if (first != null) {
            println("First field name:\n${first.name}")
            // The field value can be large (e.g. the validator set on 0x5), so we
            // print only the first few lines as a preview.
            val previewLines = 15
            val valueText = first.valueAsJson.toString()
            val lines = valueText.lines()
            val preview = lines.take(previewLines).joinToString("\n")
            val truncated = lines.size > previewLines
            println("First field value (first $previewLines lines):")
            println(preview)
            if (truncated) {
                println("... [truncated]")
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
