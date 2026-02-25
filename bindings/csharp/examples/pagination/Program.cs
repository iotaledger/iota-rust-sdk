// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();
        var address = Address.FromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c");

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
            Console.WriteLine(obj.ObjectId().ToHex());
        }
    }
}
