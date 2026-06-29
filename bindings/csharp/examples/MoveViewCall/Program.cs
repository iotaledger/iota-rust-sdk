// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: https://github.com/iotaledger/iota-rust-sdk/issues/1000

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

        if (result.Error != null)
        {
            Console.WriteLine($"Error: {result.Error}");
        }
        else if (result.Results != null)
        {
            Console.WriteLine($"Results: {result.Results}");
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

        if (jsonResult.Error != null)
        {
            Console.WriteLine($"JSON Error: {jsonResult.Error}");
        }
        else if (jsonResult.Results != null)
        {
            Console.WriteLine($"JSON Results: {jsonResult.Results}");
        }
        else
        {
            Console.WriteLine("No JSON results");
        }

        // Console.WriteLine();
        // Console.WriteLine("=== Example 3: move_view_call() with typed arguments (auction) ===");
        // Console.WriteLine();

        // var objectId = ObjectId.FromHex("0x2292ea885039babe8c320f19e0b7546ebdef2b2f6cf2be600bf994cdb51e0050");
        // var auctionArgs = new[]
        // {
        //     MoveViewArg.ObjectId(objectId),
        //     MoveViewArg.String("auc.iota")
        // };

        // var auctionResult = await client.MoveViewCall(
        //     "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d::auction::get_auction_metadata",
        //     null,
        //     auctionArgs
        // );

        // if (auctionResult.error != null)
        // {
        //     Console.WriteLine($"Auction Error: {auctionResult.error}");
        // }
        // else if (auctionResult.results != null)
        // {
        //     Console.WriteLine($"Auction Results: {auctionResult.results}");
        // }
        // else
        // {
        //     Console.WriteLine("No auction results");
        // }

        // Console.WriteLine();
        // Console.WriteLine("=== Example 4: move_view_call_json() with JSON values (auction) ===");
        // Console.WriteLine();

        // var auctionJsonArgs = new[]
        // {
        //     "\"0x2292ea885039babe8c320f19e0b7546ebdef2b2f6cf2be600bf994cdb51e0050\"",
        //     "\"auc.iota\""
        // };
        // var auctionJsonResult = await client.MoveViewCallJson(
        //     "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d::auction::get_auction_metadata",
        //     null,
        //     auctionJsonArgs
        // );

        // if (auctionJsonResult.error != null)
        // {
        //     Console.WriteLine($"Auction JSON Error: {auctionJsonResult.error}");
        // }
        // else if (auctionJsonResult.results != null)
        // {
        //     Console.WriteLine($"Auction JSON Results: {auctionJsonResult.results}");
        // }
        // else
        // {
        //     Console.WriteLine("No auction JSON results");
        // }
    }
}
