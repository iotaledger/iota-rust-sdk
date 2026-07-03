// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();
        var address = Address.Zero();
        var filter = new ObjectFilter(Owner: address);

        var objectsPage = await client.Objects(filter: filter);
        Console.WriteLine($"Owned objects({objectsPage.Data.Length}):");
        foreach (var obj in objectsPage.Data)
        {
            Console.WriteLine(obj.Id().ToHex());
        }
    }
}
