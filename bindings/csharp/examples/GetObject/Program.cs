// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Threading.Tasks;
using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        var objectId = ObjectId.FromHex("0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e");

        var obj = await client.Object(objectId, null);
        if (obj == null)
        {
            throw new Exception("missing object");
        }

        Console.WriteLine($"Object ID: {obj.ObjectId().ToHex()}");
        Console.WriteLine($"Version: {obj.Version()}");
        Console.WriteLine($"Previous transaction: {obj.PreviousTransaction().ToBase58()}");
        Console.WriteLine($"Owner: {obj.Owner()}");
        Console.WriteLine($"Storage rebate: {obj.StorageRebate()}");
        Console.WriteLine($"Type: {obj.ObjectType()}");
        Console.WriteLine($"BCS bytes: {Iota.HexEncode(obj.AsStruct().contents)}");
    }
}
