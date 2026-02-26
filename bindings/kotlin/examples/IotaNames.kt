// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example demonstrates the major IOTA Names operations:
//
// 1. Name lookup: resolve an IOTA name to an address
// 2. Reverse lookup: resolve an address back to its IOTA name
// 3. Name record details: query expiration timestamp
// 4. Check existence: verify if a name is registered
//
// All operations use dev_inspect (dry run) so no gas or signing is needed.

import iota_sdk.*
import kotlin.collections.emptyList
import kotlinx.coroutines.runBlocking

// IOTA Names configuration per network
val CONFIGS = mapOf(
    "devnet" to Pair(
        "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba",
        "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
    ),
    "mainnet" to Pair(
        "0x6d2c743607ef275bd6934fe5c2a7e5179cca6fbd2049cfa79de2310b74f3cf83",
        "0xa14e5d0481a7aa346157078e6facba3cd895d97038cd87b9f2cc24b0c6102d75"
    )
)

// Default (overridden in main based on CLI args)
var IOTA_NAMES_PACKAGE = CONFIGS["devnet"]!!.first
var IOTA_NAMES_OBJECT = CONFIGS["devnet"]!!.second

fun registryTypeTag(pkg: Address): TypeTag {
    return TypeTag.newStruct(
        StructTag(pkg, Identifier("registry"), Identifier("Registry"))
    )
}

fun nameRecordTypeTag(pkg: Address): TypeTag {
    return TypeTag.newStruct(
        StructTag(pkg, Identifier("name_record"), Identifier("NameRecord"))
    )
}

/** Example 1: Look up an IOTA name to get the associated address. */
suspend fun lookupName(client: GraphQlClient, name: String): Address? {
    val pkg = Address.fromHex(IOTA_NAMES_PACKAGE)
    val obj = ObjectId.fromHex(IOTA_NAMES_OBJECT)
    val std = Address.std()
    val sender = Address.zero()

    val builder = TransactionBuilder(sender).withClient(client)

    // 1. Get the registry
    builder.moveCall(
        pkg, Identifier("iota_names"), Identifier("registry"),
        listOf(PtbArgument.sharedMut(obj)),
        listOf(registryTypeTag(pkg)),
        listOf("iota_names"),
    )

    // 2. Create name from string
    builder.moveCall(
        pkg, Identifier("name"), Identifier("new"),
        listOf(PtbArgument.string(name)),
        emptyList(),
        listOf("name"),
    )

    // 3. Lookup name record
    builder.moveCall(
        pkg, Identifier("registry"), Identifier("lookup"),
        listOf(PtbArgument.assigned("iota_names"), PtbArgument.assigned("name")),
        emptyList(),
        listOf("name_record_opt"),
    )

    // 4. Borrow name record from option
    builder.moveCall(
        std, Identifier("option"), Identifier("borrow"),
        listOf(PtbArgument.assigned("name_record_opt")),
        listOf(nameRecordTypeTag(pkg)),
        listOf("name_record"),
    )

    // 5. Get target address from name record
    builder.moveCall(
        pkg, Identifier("name_record"), Identifier("target_address"),
        listOf(PtbArgument.assigned("name_record")),
        emptyList(),
        listOf("target_address_opt"),
    )

    // 6. Borrow address from option
    builder.moveCall(
        std, Identifier("option"), Identifier("borrow"),
        listOf(PtbArgument.assigned("target_address_opt")),
        listOf(TypeTag.newAddress()),
        listOf("target_address"),
    )

    val res = builder.dryRun(true)

    if (res.error != null) {
        if (res.error!!.contains("None") || res.error!!.contains("option")) {
            return null
        }
        throw Exception("Name lookup failed: ${res.error}")
    }

    if (res.results.isNotEmpty()) {
        val lastEffect = res.results.last()
        if (lastEffect.returnValues.isNotEmpty()) {
            val rv = lastEffect.returnValues.first()
            if (rv.typeTag.isAddress() && rv.bcs.size == 32) {
                return Address.fromBytes(rv.bcs)
            }
        }
    }
    return null
}

/** Example 2: Reverse lookup - resolve an address to its IOTA name. */
suspend fun reverseLookup(client: GraphQlClient, address: Address) {
    val pkg = Address.fromHex(IOTA_NAMES_PACKAGE)
    val obj = ObjectId.fromHex(IOTA_NAMES_OBJECT)
    val sender = Address.zero()

    val builder = TransactionBuilder(sender).withClient(client)

    // Get the shared registry
    builder.moveCall(
        pkg, Identifier("iota_names"), Identifier("registry"),
        listOf(PtbArgument.sharedMut(obj)),
        listOf(registryTypeTag(pkg)),
        listOf("registry"),
    )

    // Reverse lookup: address -> Option<Name>
    builder.moveCall(
        pkg, Identifier("registry"), Identifier("reverse_lookup"),
        listOf(PtbArgument.assigned("registry"), PtbArgument.address(address)),
        emptyList(),
        listOf("name_opt"),
    )

    val res = builder.dryRun(true)

    if (res.error != null) {
        println("  Reverse lookup failed: ${res.error}")
        return
    }

    if (res.results.isNotEmpty()) {
        val lastEffect = res.results.last()
        if (lastEffect.returnValues.isNotEmpty()) {
            val rv = lastEffect.returnValues.first()
            if (rv.bcs.isNotEmpty() && rv.bcs[0] == 1.toByte()) {
                println("  Address ${address.toHex()} has a reverse name record")
            } else {
                println("  Address ${address.toHex()} does not have a reverse name record")
            }
        }
    }
}

/** Example 3: Query name record details (target address, expiration). */
suspend fun nameRecordDetails(client: GraphQlClient, name: String) {
    // First check if the name exists to avoid option::borrow abort
    if (!checkNameExists(client, name)) {
        println("  Name '$name' is not registered, no record to query.")
        return
    }

    val pkg = Address.fromHex(IOTA_NAMES_PACKAGE)
    val obj = ObjectId.fromHex(IOTA_NAMES_OBJECT)
    val std = Address.std()
    val sender = Address.zero()

    val builder = TransactionBuilder(sender).withClient(client)

    // Get the shared registry
    builder.moveCall(
        pkg, Identifier("iota_names"), Identifier("registry"),
        listOf(PtbArgument.sharedMut(obj)),
        listOf(registryTypeTag(pkg)),
        listOf("registry"),
    )

    // Create the name object
    builder.moveCall(
        pkg, Identifier("name"), Identifier("new"),
        listOf(PtbArgument.string(name)),
        emptyList(),
        listOf("name"),
    )

    // Look up the name record
    builder.moveCall(
        pkg, Identifier("registry"), Identifier("lookup"),
        listOf(PtbArgument.assigned("registry"), PtbArgument.assigned("name")),
        emptyList(),
        listOf("name_record_opt"),
    )

    // Borrow the name record from Option
    builder.moveCall(
        std, Identifier("option"), Identifier("borrow"),
        listOf(PtbArgument.assigned("name_record_opt")),
        listOf(nameRecordTypeTag(pkg)),
        listOf("name_record"),
    )

    // Get the target address
    builder.moveCall(
        pkg, Identifier("name_record"), Identifier("target_address"),
        listOf(PtbArgument.assigned("name_record")),
        emptyList(),
        listOf("target_address_opt"),
    )

    // Get the expiration timestamp
    builder.moveCall(
        pkg, Identifier("name_record"), Identifier("expiration_timestamp_ms"),
        listOf(PtbArgument.assigned("name_record")),
        emptyList(),
        listOf("expiration"),
    )

    val res = builder.dryRun(true)

    if (res.error != null) {
        throw Exception("Name record query failed: ${res.error}")
    }

    println("  Name record details for '$name':")

    // Extract expiration (u64) from results
    for (effect in res.results) {
        for (rv in effect.returnValues) {
            if (rv.typeTag.isU64() && rv.bcs.size == 8) {
                var timestamp: Long = 0
                for (i in 0 until 8) {
                    timestamp = timestamp or ((rv.bcs[i].toLong() and 0xFF) shl (i * 8))
                }
                println("  Expiration timestamp (ms): $timestamp")
            }
        }
    }

    // Extract target address from Option<address> result (5th move call, index 4)
    if (res.results.size > 4) {
        val effect = res.results[4]
        if (effect.returnValues.isNotEmpty()) {
            val rv = effect.returnValues.first()
            if (rv.bcs.size == 33 && rv.bcs[0] == 1.toByte()) {
                val addrBytes = rv.bcs.sliceArray(1..32)
                val addr = Address.fromBytes(addrBytes)
                println("  Target address: ${addr.toHex()}")
            } else {
                println("  Target address: not set")
            }
        }
    }
}

/** Example 4: Check if a name exists in the registry. */
suspend fun checkNameExists(client: GraphQlClient, name: String): Boolean {
    val pkg = Address.fromHex(IOTA_NAMES_PACKAGE)
    val obj = ObjectId.fromHex(IOTA_NAMES_OBJECT)
    val sender = Address.zero()

    val builder = TransactionBuilder(sender).withClient(client)

    // Get the shared registry
    builder.moveCall(
        pkg, Identifier("iota_names"), Identifier("registry"),
        listOf(PtbArgument.sharedMut(obj)),
        listOf(registryTypeTag(pkg)),
        listOf("registry"),
    )

    // Create the name object
    builder.moveCall(
        pkg, Identifier("name"), Identifier("new"),
        listOf(PtbArgument.string(name)),
        emptyList(),
        listOf("name"),
    )

    // Check if the name has a record
    builder.moveCall(
        pkg, Identifier("registry"), Identifier("has_record"),
        listOf(PtbArgument.assigned("registry"), PtbArgument.assigned("name")),
        emptyList(),
        listOf("exists"),
    )

    val res = builder.dryRun(true)

    if (res.error != null) {
        throw Exception("has_record check failed: ${res.error}")
    }

    if (res.results.isNotEmpty()) {
        val lastEffect = res.results.last()
        if (lastEffect.returnValues.isNotEmpty()) {
            val rv = lastEffect.returnValues.first()
            if (rv.typeTag.isBool()) {
                return rv.bcs.firstOrNull() == 1.toByte()
            }
        }
    }
    return false
}

fun main(args: Array<String>) = runBlocking {
    try {
        val name = if (args.isNotEmpty()) args[0] else "name.iota"
        val network = if (args.size > 1) args[1] else "devnet"

        val config = CONFIGS[network] ?: CONFIGS["devnet"]!!
        IOTA_NAMES_PACKAGE = config.first
        IOTA_NAMES_OBJECT = config.second

        val client = if (network == "mainnet") GraphQlClient.newMainnet() else GraphQlClient.newDevnet()

        println("=== IOTA Names Examples ($network) ===\n")

        // Example 1: Name lookup (name -> address)
        println("1. Looking up '$name'...")
        val address = lookupName(client, name)
        if (address != null) {
            println("   Resolved to: ${address.toHex()}\n")

            // Example 2: Reverse lookup (address -> name)
            println("2. Reverse lookup for ${address.toHex()}...")
            reverseLookup(client, address)
            println()
        } else {
            println("   Name not found or expired\n")
            println("2. Skipping reverse lookup (no address to look up)\n")
        }

        // Example 3: Name record details
        println("3. Querying name record details for '$name'...")
        nameRecordDetails(client, name)
        println()

        // Example 4: Check if names exist
        println("4. Checking name existence...")
        val exists = checkNameExists(client, name)
        println("   '$name' exists: $exists")

        val fakeName = "this-name-probably-does-not-exist-12345.iota"
        val fakeExists = checkNameExists(client, fakeName)
        println("   '$fakeName' exists: $fakeExists")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
