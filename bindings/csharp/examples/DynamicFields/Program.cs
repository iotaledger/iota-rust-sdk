// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();
        var parentObjectId = Address.FromHex("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec");
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
