// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Direction
import iota_sdk.GraphQlClient
import iota_sdk.NameFormat
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val name = "name.iota"
        println("Resolving name: $name")

        val resolvedAddress = client.iotaNamesLookup(name)
        if (resolvedAddress == null) {
            println("No address resolved for $name")
            return@runBlocking
        }
        println("Resolved address: ${resolvedAddress.toHex()}")

        val defaultNameDot = client.iotaNamesDefaultName(resolvedAddress, NameFormat.DOT)
        if (defaultNameDot == null) {
            println("No default dot-format name found")
        } else {
            println("Default name (dot): $defaultNameDot")
        }

        val defaultNameAt = client.iotaNamesDefaultName(resolvedAddress, NameFormat.AT)
        if (defaultNameAt == null) {
            println("No default at-format name found")
        } else {
            println("Default name (at): ${defaultNameAt.format(NameFormat.AT)}")
        }

        val registrations = client.iotaNamesRegistrations(
            resolvedAddress,
            PaginationFilter(direction = Direction.FORWARD, limit = 10),
        )

        if (registrations.data.isEmpty()) {
            println("No IOTA Names registrations found for this address")
            return@runBlocking
        }

        println("Registrations (${registrations.data.size}):")
        for (registration in registrations.data) {
            println(
                "- ${registration.nameStr()} " +
                    "(id: ${registration.id().toHex()}, " +
                    "expires_at_ms: ${registration.expirationTimestampMs()})"
            )
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
