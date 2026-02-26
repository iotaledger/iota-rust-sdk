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

import Foundation
import IotaSDK

// IOTA Names configuration per network
struct IotaNamesConfig {
  let packageHex: String
  let objectHex: String
}

let iotaNamesConfigs: [String: IotaNamesConfig] = [
  "devnet": IotaNamesConfig(
    packageHex: "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba",
    objectHex: "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
  ),
  "mainnet": IotaNamesConfig(
    packageHex: "0x6d2c743607ef275bd6934fe5c2a7e5179cca6fbd2049cfa79de2310b74f3cf83",
    objectHex: "0xa14e5d0481a7aa346157078e6facba3cd895d97038cd87b9f2cc24b0c6102d75"
  ),
]

// Active config (set in main based on CLI args)
var iotaNamesPackageHex = iotaNamesConfigs["devnet"]!.packageHex
var iotaNamesObjectHex = iotaNamesConfigs["devnet"]!.objectHex

func registryTypeTag(_ pkg: Address) throws -> TypeTag {
  return TypeTag.newStruct(
    structTag: StructTag(
      address: pkg,
      module: try Identifier(identifier: "registry"),
      name: try Identifier(identifier: "Registry")
    ))
}

func nameRecordTypeTag(_ pkg: Address) throws -> TypeTag {
  return TypeTag.newStruct(
    structTag: StructTag(
      address: pkg,
      module: try Identifier(identifier: "name_record"),
      name: try Identifier(identifier: "NameRecord")
    ))
}

/// Example 1: Look up an IOTA name to get the associated address.
func lookupName(client: GraphQlClient, name: String) async throws -> Address? {
  let pkg = try Address.fromHex(hex: iotaNamesPackageHex)
  let obj = try ObjectId.fromHex(hex: iotaNamesObjectHex)
  let std = Address.std()
  let sender = Address.zero()

  let builder = TransactionBuilder(sender: sender).withClient(client: client)

  // 1. Get the registry
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "iota_names"),
    function: Identifier(identifier: "registry"),
    arguments: [PtbArgument.sharedMut(id: obj)],
    typeArgs: [try registryTypeTag(pkg)],
    names: ["iota_names"]
  )

  // 2. Create name from string
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "name"),
    function: Identifier(identifier: "new"),
    arguments: [PtbArgument.string(string: name)],
    names: ["name"]
  )

  // 3. Lookup name record
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "registry"),
    function: Identifier(identifier: "lookup"),
    arguments: [PtbArgument.assigned(name: "iota_names"), PtbArgument.assigned(name: "name")],
    names: ["name_record_opt"]
  )

  // 4. Borrow name record from option
  _ = try builder.moveCall(
    package: std,
    module: Identifier(identifier: "option"),
    function: Identifier(identifier: "borrow"),
    arguments: [PtbArgument.assigned(name: "name_record_opt")],
    typeArgs: [try nameRecordTypeTag(pkg)],
    names: ["name_record"]
  )

  // 5. Get target address from name record
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "name_record"),
    function: Identifier(identifier: "target_address"),
    arguments: [PtbArgument.assigned(name: "name_record")],
    names: ["target_address_opt"]
  )

  // 6. Borrow address from option
  _ = try builder.moveCall(
    package: std,
    module: Identifier(identifier: "option"),
    function: Identifier(identifier: "borrow"),
    arguments: [PtbArgument.assigned(name: "target_address_opt")],
    typeArgs: [TypeTag.newAddress()],
    names: ["target_address"]
  )

  let res = try await builder.dryRun(skipChecks: true)

  if let error = res.error {
    if error.contains("None") || error.contains("option") {
      return nil
    }
    throw NSError(
      domain: "IotaNames", code: 1,
      userInfo: [NSLocalizedDescriptionKey: "Name lookup failed: \(error)"])
  }

  if let lastEffect = res.results.last,
    let rv = lastEffect.returnValues.first,
    rv.typeTag.isAddress() && rv.bcs.count == 32
  {
    return try Address.fromBytes(bytes: rv.bcs)
  }
  return nil
}

/// Example 2: Reverse lookup - resolve an address to its IOTA name.
func reverseLookup(client: GraphQlClient, address: Address) async throws {
  let pkg = try Address.fromHex(hex: iotaNamesPackageHex)
  let obj = try ObjectId.fromHex(hex: iotaNamesObjectHex)
  let sender = Address.zero()

  let builder = TransactionBuilder(sender: sender).withClient(client: client)

  // Get the shared registry
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "iota_names"),
    function: Identifier(identifier: "registry"),
    arguments: [PtbArgument.sharedMut(id: obj)],
    typeArgs: [try registryTypeTag(pkg)],
    names: ["registry"]
  )

  // Reverse lookup: address -> Option<Name>
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "registry"),
    function: Identifier(identifier: "reverse_lookup"),
    arguments: [
      PtbArgument.assigned(name: "registry"),
      PtbArgument.address(address: address),
    ],
    names: ["name_opt"]
  )

  let res = try await builder.dryRun(skipChecks: true)

  if let error = res.error {
    print("  Reverse lookup failed: \(error)")
    return
  }

  if let lastEffect = res.results.last,
    let rv = lastEffect.returnValues.first
  {
    if !rv.bcs.isEmpty && rv.bcs[0] == 1 {
      print("  Address \(address.toHex()) has a reverse name record")
    } else {
      print("  Address \(address.toHex()) does not have a reverse name record")
    }
  }
}

/// Example 3: Query name record details (target address, expiration).
func nameRecordDetails(client: GraphQlClient, name: String) async throws {
  // First check if the name exists to avoid option::borrow abort
  if try await !checkNameExists(client: client, name: name) {
    print("  Name '\(name)' is not registered, no record to query.")
    return
  }

  let pkg = try Address.fromHex(hex: iotaNamesPackageHex)
  let obj = try ObjectId.fromHex(hex: iotaNamesObjectHex)
  let std = Address.std()
  let sender = Address.zero()

  let builder = TransactionBuilder(sender: sender).withClient(client: client)

  // Get the shared registry
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "iota_names"),
    function: Identifier(identifier: "registry"),
    arguments: [PtbArgument.sharedMut(id: obj)],
    typeArgs: [try registryTypeTag(pkg)],
    names: ["registry"]
  )

  // Create the name object
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "name"),
    function: Identifier(identifier: "new"),
    arguments: [PtbArgument.string(string: name)],
    names: ["name"]
  )

  // Look up the name record
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "registry"),
    function: Identifier(identifier: "lookup"),
    arguments: [
      PtbArgument.assigned(name: "registry"), PtbArgument.assigned(name: "name"),
    ],
    names: ["name_record_opt"]
  )

  // Borrow the name record from Option
  _ = try builder.moveCall(
    package: std,
    module: Identifier(identifier: "option"),
    function: Identifier(identifier: "borrow"),
    arguments: [PtbArgument.assigned(name: "name_record_opt")],
    typeArgs: [try nameRecordTypeTag(pkg)],
    names: ["name_record"]
  )

  // Get the target address
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "name_record"),
    function: Identifier(identifier: "target_address"),
    arguments: [PtbArgument.assigned(name: "name_record")],
    names: ["target_address_opt"]
  )

  // Get the expiration timestamp
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "name_record"),
    function: Identifier(identifier: "expiration_timestamp_ms"),
    arguments: [PtbArgument.assigned(name: "name_record")],
    names: ["expiration"]
  )

  let res = try await builder.dryRun(skipChecks: true)

  if let error = res.error {
    throw NSError(
      domain: "IotaNames", code: 1,
      userInfo: [NSLocalizedDescriptionKey: "Name record query failed: \(error)"])
  }

  print("  Name record details for '\(name)':")

  // Extract expiration (u64)
  for effect in res.results {
    for rv in effect.returnValues {
      if rv.typeTag.isU64() && rv.bcs.count == 8 {
        let timestamp = rv.bcs.withUnsafeBytes { $0.load(as: UInt64.self) }
        print("  Expiration timestamp (ms): \(timestamp)")
      }
    }
  }

  // Extract target address from Option<address> (5th move call, index 4)
  if res.results.count > 4 {
    let effect = res.results[4]
    if let rv = effect.returnValues.first {
      if rv.bcs.count == 33 && rv.bcs[0] == 1 {
        let addrBytes = Data(rv.bcs[1...32])
        let addr = try Address.fromBytes(bytes: addrBytes)
        print("  Target address: \(addr.toHex())")
      } else {
        print("  Target address: not set")
      }
    }
  }
}

/// Example 4: Check if a name exists in the registry.
func checkNameExists(client: GraphQlClient, name: String) async throws -> Bool {
  let pkg = try Address.fromHex(hex: iotaNamesPackageHex)
  let obj = try ObjectId.fromHex(hex: iotaNamesObjectHex)
  let sender = Address.zero()

  let builder = TransactionBuilder(sender: sender).withClient(client: client)

  // Get the shared registry
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "iota_names"),
    function: Identifier(identifier: "registry"),
    arguments: [PtbArgument.sharedMut(id: obj)],
    typeArgs: [try registryTypeTag(pkg)],
    names: ["registry"]
  )

  // Create the name object
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "name"),
    function: Identifier(identifier: "new"),
    arguments: [PtbArgument.string(string: name)],
    names: ["name"]
  )

  // Check if the name has a record
  _ = try builder.moveCall(
    package: pkg,
    module: Identifier(identifier: "registry"),
    function: Identifier(identifier: "has_record"),
    arguments: [
      PtbArgument.assigned(name: "registry"), PtbArgument.assigned(name: "name"),
    ],
    names: ["exists"]
  )

  let res = try await builder.dryRun(skipChecks: true)

  if let error = res.error {
    throw NSError(
      domain: "IotaNames", code: 1,
      userInfo: [NSLocalizedDescriptionKey: "has_record check failed: \(error)"])
  }

  if let lastEffect = res.results.last,
    let rv = lastEffect.returnValues.first,
    rv.typeTag.isBool()
  {
    return rv.bcs.first == 1
  }
  return false
}

@main
struct IotaNamesExample {
  static func main() async throws {
    let args = CommandLine.arguments
    let name = args.count > 1 ? args[1] : "name.iota"
    let network = args.count > 2 ? args[2] : "devnet"

    if let config = iotaNamesConfigs[network] {
      iotaNamesPackageHex = config.packageHex
      iotaNamesObjectHex = config.objectHex
    }

    let client = network == "mainnet" ? GraphQlClient.newMainnet() : GraphQlClient.newDevnet()

    print("=== IOTA Names Examples (\(network)) ===\n")

    // Example 1: Name lookup (name -> address)
    print("1. Looking up '\(name)'...")
    let address = try await lookupName(client: client, name: name)
    if let address = address {
      print("   Resolved to: \(address.toHex())\n")

      // Example 2: Reverse lookup (address -> name)
      print("2. Reverse lookup for \(address.toHex())...")
      try await reverseLookup(client: client, address: address)
      print("")
    } else {
      print("   Name not found or expired\n")
      print("2. Skipping reverse lookup (no address to look up)\n")
    }

    // Example 3: Name record details
    print("3. Querying name record details for '\(name)'...")
    try await nameRecordDetails(client: client, name: name)
    print("")

    // Example 4: Check if names exist
    print("4. Checking name existence...")
    let exists = try await checkNameExists(client: client, name: name)
    print("   '\(name)' exists: \(exists)")

    let fakeName = "this-name-probably-does-not-exist-12345.iota"
    let fakeExists = try await checkNameExists(client: client, name: fakeName)
    print("   '\(fakeName)' exists: \(fakeExists)")
  }
}
