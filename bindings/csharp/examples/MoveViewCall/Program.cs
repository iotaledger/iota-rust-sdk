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

        Console.WriteLine("=== Example 1: move_view_call() with typed arguments (blake2b256) ===");
        Console.WriteLine();

        var hashArgs = new[] { MoveViewArg.U8Vec(new byte[] { 0, 1, 2 }) };

        var result = await client.MoveViewCall("0x2::hash::blake2b256", null, hashArgs);

        if (result.error != null)
        {
            Console.WriteLine($"Error: {result.error}");
        }
        else if (result.results != null)
        {
            Console.WriteLine($"Results: {result.results}");
        }
        else
        {
            Console.WriteLine("No results");
        }

        Console.WriteLine();
        Console.WriteLine("=== Example 2: move_view_call_json() with JSON values (blake2b256) ===");
        Console.WriteLine();

        var jsonArgs = new[] { "[0, 1, 2]" };
        var jsonResult = await client.MoveViewCallJson("0x2::hash::blake2b256", null, jsonArgs);

        if (jsonResult.error != null)
        {
            Console.WriteLine($"JSON Error: {jsonResult.error}");
        }
        else if (jsonResult.results != null)
        {
            Console.WriteLine($"JSON Results: {jsonResult.results}");
        }
        else
        {
            Console.WriteLine("No JSON results");
        }

        Console.WriteLine();
        Console.WriteLine("=== Example 3: move_view_call() with typed arguments (auction) ===");
        Console.WriteLine();

        var objectId = ObjectId.FromHex("0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b");
        var auctionArgs = new[]
        {
            MoveViewArg.ObjectId(objectId),
            MoveViewArg.String("auc.iota")
        };

        var auctionResult = await client.MoveViewCall(
            "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
            null,
            auctionArgs
        );

        if (auctionResult.error != null)
        {
            Console.WriteLine($"Auction Error: {auctionResult.error}");
        }
        else if (auctionResult.results != null)
        {
            Console.WriteLine($"Auction Results: {auctionResult.results}");
        }
        else
        {
            Console.WriteLine("No auction results");
        }

        Console.WriteLine();
        Console.WriteLine("=== Example 4: move_view_call_json() with JSON values (auction) ===");
        Console.WriteLine();

        var auctionJsonArgs = new[]
        {
            "\"0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b\"",
            "\"auc.iota\""
        };
        var auctionJsonResult = await client.MoveViewCallJson(
            "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
            null,
            auctionJsonArgs
        );

        if (auctionJsonResult.error != null)
        {
            Console.WriteLine($"Auction JSON Error: {auctionJsonResult.error}");
        }
        else if (auctionJsonResult.results != null)
        {
            Console.WriteLine($"Auction JSON Results: {auctionJsonResult.results}");
        }
        else
        {
            Console.WriteLine("No auction JSON results");
        }
    }
}
