// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    // The `view_demo` package published on testnet.
    const string Package = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4";

    // A shared `view_demo::shop::Shop` created when the package was published.
    const string Shop = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20";

    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        Console.WriteLine("=== Example 1: MoveViewCall() with typed arguments (primitives) ===");
        Console.WriteLine();

        var priceArgs = new[] { MoveViewArg.U64(100), MoveViewArg.U64(25) };

        var result = await client.MoveViewCall($"{Package}::shop::discounted_price", null, priceArgs);

        if (result.Error != null)
        {
            Console.WriteLine($"Error: {result.Error}");
        }
        else if (result.Results != null)
        {
            Console.WriteLine($"Results: {string.Join(", ", result.Results)}");
        }
        else
        {
            Console.WriteLine("No results");
        }

        Console.WriteLine();
        Console.WriteLine("=== Example 2: MoveViewCallJson() with JSON values (primitives) ===");
        Console.WriteLine();

        // `u64` is passed as a string so large values survive JSON.
        var jsonArgs = new[] { "\"100\"", "\"25\"" };
        var jsonResult = await client.MoveViewCallJson($"{Package}::shop::discounted_price", null, jsonArgs);

        if (jsonResult.Error != null)
        {
            Console.WriteLine($"JSON Error: {jsonResult.Error}");
        }
        else if (jsonResult.Results != null)
        {
            Console.WriteLine($"JSON Results: {string.Join(", ", jsonResult.Results)}");
        }
        else
        {
            Console.WriteLine("No JSON results");
        }

        Console.WriteLine();
        Console.WriteLine("=== Example 3: MoveViewCall() with typed arguments (shared object) ===");
        Console.WriteLine();

        var objectId = ObjectId.FromHex(Shop);
        var shopArgs = new[]
        {
            MoveViewArg.ObjectId(objectId),
            MoveViewArg.U64(1)
        };

        var shopResult = await client.MoveViewCall($"{Package}::shop::sale_at", null, shopArgs);

        if (shopResult.Error != null)
        {
            Console.WriteLine($"Shop Error: {shopResult.Error}");
        }
        else if (shopResult.Results != null)
        {
            Console.WriteLine($"Shop Results: {string.Join(", ", shopResult.Results)}");
        }
        else
        {
            Console.WriteLine("No shop results");
        }

        Console.WriteLine();
        Console.WriteLine("=== Example 4: MoveViewCallJson() with JSON values (shared object) ===");
        Console.WriteLine();

        var shopJsonArgs = new[] { $"\"{Shop}\"", "\"1\"" };
        var shopJsonResult = await client.MoveViewCallJson($"{Package}::shop::sale_at", null, shopJsonArgs);

        if (shopJsonResult.Error != null)
        {
            Console.WriteLine($"Shop JSON Error: {shopJsonResult.Error}");
        }
        else if (shopJsonResult.Results != null)
        {
            Console.WriteLine($"Shop JSON Results: {string.Join(", ", shopJsonResult.Results)}");
        }
        else
        {
            Console.WriteLine("No shop JSON results");
        }
    }
}
