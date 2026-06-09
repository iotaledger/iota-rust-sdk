// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();
        var address = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        var allObjects = new List<IotaSdk.Object>();
        string? nextCursor = null;

        while (true)
        {
            Console.WriteLine($"Fetching page with cursor: {nextCursor}");
            var page = await client.Objects(
                new ObjectFilter(owner: address),
                new PaginationFilter(Direction.Forward, nextCursor, 1)
            );
            allObjects.AddRange(page.data);

            if (page.pageInfo.hasNextPage)
            {
                nextCursor = page.pageInfo.endCursor;
            }
            else
            {
                break;
            }
        }

        Console.WriteLine($"{allObjects.Count} objects fetched:");
        foreach (var obj in allObjects)
        {
            Console.WriteLine(obj.Id().ToHex());
        }
    }
}
