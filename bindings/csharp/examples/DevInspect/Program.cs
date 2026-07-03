// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var sender = Address.Zero();

        var iotaNamesPackageAddress = Address.FromHex("0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea");
        var iotaNamesObjectId = ObjectId.FromHex("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec");
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
            [],
            new[] { "name" }
        );

        builder.MoveCall(
            iotaNamesPackageAddress,
            new Identifier("registry"),
            new Identifier("lookup"),
            new[] { PtbArgument.Assigned("iota_names"), PtbArgument.Assigned("name") },
            [],
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
            [],
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

        if (res.Error != null)
        {
            throw new Exception($"Failed to lookup name: {res.Error}");
        }

        if (res.Results.Length > 0)
        {
            var lastEffect = res.Results[res.Results.Length - 1];
            if (lastEffect.ReturnValues.Length > 0)
            {
                var returnValue = lastEffect.ReturnValues[0];
                if (returnValue.TypeTag.IsAddress() && returnValue.Bcs.Length == 32)
                {
                    var resolvedAddress = Address.FromBytes(returnValue.Bcs);
                    Console.WriteLine($"Resolved address: {resolvedAddress.ToHex()}");
                }
                else
                {
                    Console.WriteLine($"Last result is not an address type or has wrong length: {returnValue.Bcs.Length}");
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
