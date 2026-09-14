// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GrpcClient.NewTestnet();

        var owner = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        // First page: 10 results, no filter on type. The returned page includes a
        // `NextPageToken` to feed back in for the following page.
        var page = await client.OwnedObjects(owner, null, 10, null);
        Console.WriteLine($"First page: {page.Objects.Length} objects");
        foreach (var obj in page.Objects)
        {
            Console.WriteLine($"  {obj.Id().ToHex()}");
        }
        if (page.NextPageToken != null)
        {
            Console.WriteLine("  ...more pages available");
        }

        // Auto-paginate: only IOTA coins, capped at 50 across all pages.
        var coins = await client.AllOwnedObjects(owner, StructTag.NewGasCoin(), 50);
        Console.WriteLine("---");
        Console.WriteLine($"Up to 50 IOTA coin objects ({coins.Length} returned):");
        foreach (var obj in coins)
        {
            Console.WriteLine($"  {obj.Id().ToHex()}");
        }
    }
}
