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
        var parentObjectId = Address.FromHex("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342");
        var page = await client.DynamicFields(parentObjectId);

        Console.WriteLine($"Page size: {page.data.Length}");
        if (page.data.Length > 0)
        {
            Console.WriteLine("First field name:");
            Console.WriteLine(page.data[0].name);
            Console.WriteLine("First field value:");
            Console.WriteLine(page.data[0].valueAsJson);
        }
    }
}
