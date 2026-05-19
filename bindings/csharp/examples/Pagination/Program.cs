// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();
        var address = Address.FromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522");
        await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(address, client);

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
