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

using IotaSdk;

class Program
{
    // IOTA Names configuration per network
    static readonly Dictionary<string, (string Package, string Object)> Configs = new()
    {
        ["devnet"] = (
            "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba",
            "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
        ),
        ["mainnet"] = (
            "0x6d2c743607ef275bd6934fe5c2a7e5179cca6fbd2049cfa79de2310b74f3cf83",
            "0xa14e5d0481a7aa346157078e6facba3cd895d97038cd87b9f2cc24b0c6102d75"
        ),
    };

    static string IotaNamesPackage = Configs["devnet"].Package;
    static string IotaNamesObject = Configs["devnet"].Object;

    static TypeTag RegistryTypeTag(Address pkg) =>
        TypeTag.NewStruct(new StructTag(pkg, new Identifier("registry"), new Identifier("Registry")));

    static TypeTag NameRecordTypeTag(Address pkg) =>
        TypeTag.NewStruct(new StructTag(pkg, new Identifier("name_record"), new Identifier("NameRecord")));

    /// <summary>Example 1: Look up an IOTA name to get the associated address.</summary>
    static async Task<Address?> LookupName(GraphQlClient client, string name)
    {
        var pkg = Address.FromHex(IotaNamesPackage);
        var obj = ObjectId.FromHex(IotaNamesObject);
        var std = Address.Std();
        var sender = Address.Zero();

        var builder = new TransactionBuilder(sender).WithClient(client);

        // 1. Get the registry
        builder.MoveCall(
            pkg, new Identifier("iota_names"), new Identifier("registry"),
            new[] { PtbArgument.SharedMut(obj) },
            new[] { RegistryTypeTag(pkg) },
            new[] { "iota_names" }
        );

        // 2. Create name from string
        builder.MoveCall(
            pkg, new Identifier("name"), new Identifier("new"),
            new[] { PtbArgument.String(name) },
            Array.Empty<TypeTag>(),
            new[] { "name" }
        );

        // 3. Lookup name record
        builder.MoveCall(
            pkg, new Identifier("registry"), new Identifier("lookup"),
            new[] { PtbArgument.Assigned("iota_names"), PtbArgument.Assigned("name") },
            Array.Empty<TypeTag>(),
            new[] { "name_record_opt" }
        );

        // 4. Borrow name record from option
        builder.MoveCall(
            std, new Identifier("option"), new Identifier("borrow"),
            new[] { PtbArgument.Assigned("name_record_opt") },
            new[] { NameRecordTypeTag(pkg) },
            new[] { "name_record" }
        );

        // 5. Get target address from name record
        builder.MoveCall(
            pkg, new Identifier("name_record"), new Identifier("target_address"),
            new[] { PtbArgument.Assigned("name_record") },
            Array.Empty<TypeTag>(),
            new[] { "target_address_opt" }
        );

        // 6. Borrow address from option
        builder.MoveCall(
            std, new Identifier("option"), new Identifier("borrow"),
            new[] { PtbArgument.Assigned("target_address_opt") },
            new[] { TypeTag.NewAddress() },
            new[] { "target_address" }
        );

        var res = await builder.DryRun(true);

        if (res.error != null)
        {
            if (res.error.Contains("None") || res.error.Contains("option"))
                return null;
            throw new Exception($"Name lookup failed: {res.error}");
        }

        if (res.results.Length > 0)
        {
            var lastEffect = res.results[res.results.Length - 1];
            if (lastEffect.returnValues.Length > 0)
            {
                var rv = lastEffect.returnValues[0];
                if (rv.typeTag.IsAddress() && rv.bcs.Length == 32)
                    return Address.FromBytes(rv.bcs);
            }
        }

        return null;
    }

    /// <summary>Example 2: Reverse lookup - resolve an address to its IOTA name.</summary>
    static async Task ReverseLookup(GraphQlClient client, Address address)
    {
        var pkg = Address.FromHex(IotaNamesPackage);
        var obj = ObjectId.FromHex(IotaNamesObject);
        var sender = Address.Zero();

        var builder = new TransactionBuilder(sender).WithClient(client);

        // Get the shared registry
        builder.MoveCall(
            pkg, new Identifier("iota_names"), new Identifier("registry"),
            new[] { PtbArgument.SharedMut(obj) },
            new[] { RegistryTypeTag(pkg) },
            new[] { "registry" }
        );

        // Reverse lookup: address -> Option<Name>
        builder.MoveCall(
            pkg, new Identifier("registry"), new Identifier("reverse_lookup"),
            new[] { PtbArgument.Assigned("registry"), PtbArgument.Address(address) },
            Array.Empty<TypeTag>(),
            new[] { "name_opt" }
        );

        var res = await builder.DryRun(true);

        if (res.error != null)
        {
            Console.WriteLine($"  Reverse lookup failed: {res.error}");
            return;
        }

        if (res.results.Length > 0)
        {
            var lastEffect = res.results[res.results.Length - 1];
            if (lastEffect.returnValues.Length > 0)
            {
                var rv = lastEffect.returnValues[0];
                if (rv.bcs.Length > 0 && rv.bcs[0] == 1)
                    Console.WriteLine($"  Address {address.ToHex()} has a reverse name record");
                else
                    Console.WriteLine($"  Address {address.ToHex()} does not have a reverse name record");
            }
        }
    }

    /// <summary>Example 3: Query name record details (target address, expiration).</summary>
    static async Task NameRecordDetails(GraphQlClient client, string name)
    {
        // First check if the name exists to avoid option::borrow abort
        if (!await CheckNameExists(client, name))
        {
            Console.WriteLine($"  Name '{name}' is not registered, no record to query.");
            return;
        }

        var pkg = Address.FromHex(IotaNamesPackage);
        var obj = ObjectId.FromHex(IotaNamesObject);
        var std = Address.Std();
        var sender = Address.Zero();

        var builder = new TransactionBuilder(sender).WithClient(client);

        // Get the shared registry
        builder.MoveCall(
            pkg, new Identifier("iota_names"), new Identifier("registry"),
            new[] { PtbArgument.SharedMut(obj) },
            new[] { RegistryTypeTag(pkg) },
            new[] { "registry" }
        );

        // Create the name object
        builder.MoveCall(
            pkg, new Identifier("name"), new Identifier("new"),
            new[] { PtbArgument.String(name) },
            Array.Empty<TypeTag>(),
            new[] { "name" }
        );

        // Look up the name record
        builder.MoveCall(
            pkg, new Identifier("registry"), new Identifier("lookup"),
            new[] { PtbArgument.Assigned("registry"), PtbArgument.Assigned("name") },
            Array.Empty<TypeTag>(),
            new[] { "name_record_opt" }
        );

        // Borrow the name record from Option
        builder.MoveCall(
            std, new Identifier("option"), new Identifier("borrow"),
            new[] { PtbArgument.Assigned("name_record_opt") },
            new[] { NameRecordTypeTag(pkg) },
            new[] { "name_record" }
        );

        // Get the target address
        builder.MoveCall(
            pkg, new Identifier("name_record"), new Identifier("target_address"),
            new[] { PtbArgument.Assigned("name_record") },
            Array.Empty<TypeTag>(),
            new[] { "target_address_opt" }
        );

        // Get the expiration timestamp
        builder.MoveCall(
            pkg, new Identifier("name_record"), new Identifier("expiration_timestamp_ms"),
            new[] { PtbArgument.Assigned("name_record") },
            Array.Empty<TypeTag>(),
            new[] { "expiration" }
        );

        var res = await builder.DryRun(true);

        if (res.error != null)
            throw new Exception($"Name record query failed: {res.error}");

        Console.WriteLine($"  Name record details for '{name}':");

        // Extract expiration (u64) from results
        foreach (var effect in res.results)
        {
            foreach (var rv in effect.returnValues)
            {
                if (rv.typeTag.IsU64() && rv.bcs.Length == 8)
                {
                    var timestamp = BitConverter.ToUInt64(rv.bcs, 0);
                    Console.WriteLine($"  Expiration timestamp (ms): {timestamp}");
                }
            }
        }

        // Extract target address from the Option<address> result (5th move call)
        if (res.results.Length > 4)
        {
            var effect = res.results[4];
            if (effect.returnValues.Length > 0)
            {
                var rv = effect.returnValues[0];
                if (rv.bcs.Length == 33 && rv.bcs[0] == 1)
                {
                    var addrBytes = new byte[32];
                    Array.Copy(rv.bcs, 1, addrBytes, 0, 32);
                    var addr = Address.FromBytes(addrBytes);
                    Console.WriteLine($"  Target address: {addr.ToHex()}");
                }
                else
                {
                    Console.WriteLine("  Target address: not set");
                }
            }
        }
    }

    /// <summary>Example 4: Check if a name exists in the registry.</summary>
    static async Task<bool> CheckNameExists(GraphQlClient client, string name)
    {
        var pkg = Address.FromHex(IotaNamesPackage);
        var obj = ObjectId.FromHex(IotaNamesObject);
        var sender = Address.Zero();

        var builder = new TransactionBuilder(sender).WithClient(client);

        // Get the shared registry
        builder.MoveCall(
            pkg, new Identifier("iota_names"), new Identifier("registry"),
            new[] { PtbArgument.SharedMut(obj) },
            new[] { RegistryTypeTag(pkg) },
            new[] { "registry" }
        );

        // Create the name object
        builder.MoveCall(
            pkg, new Identifier("name"), new Identifier("new"),
            new[] { PtbArgument.String(name) },
            Array.Empty<TypeTag>(),
            new[] { "name" }
        );

        // Check if the name has a record
        builder.MoveCall(
            pkg, new Identifier("registry"), new Identifier("has_record"),
            new[] { PtbArgument.Assigned("registry"), PtbArgument.Assigned("name") },
            Array.Empty<TypeTag>(),
            new[] { "exists" }
        );

        var res = await builder.DryRun(true);

        if (res.error != null)
            throw new Exception($"has_record check failed: {res.error}");

        if (res.results.Length > 0)
        {
            var lastEffect = res.results[res.results.Length - 1];
            if (lastEffect.returnValues.Length > 0)
            {
                var rv = lastEffect.returnValues[0];
                if (rv.typeTag.IsBool())
                    return rv.bcs[0] == 1;
            }
        }

        return false;
    }

    static async Task Main(string[] args)
    {
        var name = args.Length > 0 ? args[0] : "name.iota";
        var network = args.Length > 1 ? args[1] : "devnet";

        if (Configs.ContainsKey(network))
        {
            IotaNamesPackage = Configs[network].Package;
            IotaNamesObject = Configs[network].Object;
        }

        var client = network == "mainnet"
            ? GraphQlClient.NewMainnet()
            : GraphQlClient.NewDevnet();

        Console.WriteLine($"=== IOTA Names Examples ({network}) ===\n");

        // Example 1: Name lookup (name -> address)
        Console.WriteLine($"1. Looking up '{name}'...");
        var address = await LookupName(client, name);
        if (address != null)
        {
            Console.WriteLine($"   Resolved to: {address.ToHex()}\n");

            // Example 2: Reverse lookup (address -> name)
            Console.WriteLine($"2. Reverse lookup for {address.ToHex()}...");
            await ReverseLookup(client, address);
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine("   Name not found or expired\n");
            Console.WriteLine("2. Skipping reverse lookup (no address to look up)\n");
        }

        // Example 3: Name record details
        Console.WriteLine($"3. Querying name record details for '{name}'...");
        await NameRecordDetails(client, name);
        Console.WriteLine();

        // Example 4: Check if names exist
        Console.WriteLine("4. Checking name existence...");
        var exists = await CheckNameExists(client, name);
        Console.WriteLine($"   '{name}' exists: {exists}");

        var fakeName = "this-name-probably-does-not-exist-12345.iota";
        exists = await CheckNameExists(client, fakeName);
        Console.WriteLine($"   '{fakeName}' exists: {exists}");
    }
}
