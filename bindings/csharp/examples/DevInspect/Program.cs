// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        var sender = Address.Zero();

        var iotaNamesPackageAddress = Address.FromHex("0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba");
        var iotaNamesObjectId = ObjectId.FromHex("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342");
        var stdAddress = Address.Std();

        var name = "name.iota";
        Console.WriteLine($"Looking up name: {name}");

        var builder = new TransactionBuilder(sender).WithClient(client);

        builder.MoveCall(
            iotaNamesPackageAddress,
            new Identifier("iota_names"),
            new Identifier("registry"),
            new[] { PtbArgument.SharedMut(iotaNamesObjectId) },
            new[] { TypeTag.NewStruct(new StructTag(iotaNamesPackageAddress, new Identifier("registry"), new Identifier("Registry"))) },
            new[] { "iota_names" }
        );

        builder.MoveCall(
            iotaNamesPackageAddress,
            new Identifier("name"),
            new Identifier("new"),
            new[] { PtbArgument.String(name) },
            null,
            new[] { "name" }
        );

        builder.MoveCall(
            iotaNamesPackageAddress,
            new Identifier("registry"),
            new Identifier("lookup"),
            new[] { PtbArgument.Assigned("iota_names"), PtbArgument.Assigned("name") },
            null,
            new[] { "name_record_opt" }
        );

        builder.MoveCall(
            stdAddress,
            new Identifier("option"),
            new Identifier("borrow"),
            new[] { PtbArgument.Assigned("name_record_opt") },
            new[] { TypeTag.NewStruct(new StructTag(iotaNamesPackageAddress, new Identifier("name_record"), new Identifier("NameRecord"))) },
            new[] { "name_record" }
        );

        builder.MoveCall(
            iotaNamesPackageAddress,
            new Identifier("name_record"),
            new Identifier("target_address"),
            new[] { PtbArgument.Assigned("name_record") },
            null,
            new[] { "target_address_opt" }
        );

        builder.MoveCall(
            stdAddress,
            new Identifier("option"),
            new Identifier("borrow"),
            new[] { PtbArgument.Assigned("target_address_opt") },
            new[] { TypeTag.NewAddress() },
            new[] { "target_address" }
        );

        var res = await builder.DryRun(true);

        if (res.error != null)
        {
            throw new Exception($"Failed to lookup name: {res.error}");
        }

        if (res.results.Length > 0)
        {
            var lastEffect = res.results[res.results.Length - 1];
            if (lastEffect.returnValues.Length > 0)
            {
                var returnValue = lastEffect.returnValues[0];
                if (returnValue.typeTag.IsAddress() && returnValue.bcs.Length == 32)
                {
                    var resolvedAddress = Address.FromBytes(returnValue.bcs);
                    Console.WriteLine($"Resolved address: {resolvedAddress.ToHex()}");
                }
                else
                {
                    Console.WriteLine($"Last result is not an address type or has wrong length: {returnValue.bcs.Length}");
                }
            }
            else
            {
                Console.WriteLine("No return value in last effect");
            }
        }
        else
        {
            Console.WriteLine("No results found");
        }
    }
}
