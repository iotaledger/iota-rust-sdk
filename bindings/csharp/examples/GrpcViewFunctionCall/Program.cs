// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    // The `view_demo` package published on testnet.
    const string Package = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4";

    // A shared `view_demo::shop::Shop` created when the package was published.
    const string Shop = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20";

    static string Describe(ViewFunctionCallOutputs outputs)
    {
        if (outputs.ReturnValues != null)
        {
            return $"returned [{string.Join(", ", outputs.ReturnValues.Select(value => value.Json))}]";
        }
        return $"aborted ({outputs.ExecutionError?.Source})";
    }

    static async Task Main(string[] args)
    {
        try
        {
            var client = GrpcClient.NewTestnet();

            // A single call. `discounted_price` is declared `#[view]` in the package.
            var outputs = await client.ViewFunctionCall(
                $"{Package}::shop::discounted_price",
                null,
                new[] { MoveViewArg.U64(100), MoveViewArg.U64(25) });
            Console.WriteLine($"discounted_price: {Describe(outputs)}");

            // Three calls in one request: the call from above, the same function with
            // a discount over 100% so that it aborts, and a function that is not
            // declared `#[view]`. Each call runs on its own, so the rejected one does
            // not affect the others.
            var shop = ObjectId.FromHex(Shop);
            var results = await client.ViewFunctionCalls(new[]
            {
                new ViewFunctionCallInput(
                    $"{Package}::shop::discounted_price",
                    new TypeTag[] { },
                    new[] { MoveViewArg.U64(100), MoveViewArg.U64(25) }),
                new ViewFunctionCallInput(
                    $"{Package}::shop::discounted_price",
                    new TypeTag[] { },
                    new[] { MoveViewArg.U64(100), MoveViewArg.U64(200) }),
                new ViewFunctionCallInput(
                    $"{Package}::shop::record_sale",
                    new TypeTag[] { },
                    new[] { MoveViewArg.ObjectId(shop), MoveViewArg.U64(5) }),
            });

            var names = new[] { "priced", "over-discounted", "record_sale" };
            foreach (var (name, result) in names.Zip(results))
            {
                if (result.Outputs != null)
                {
                    Console.WriteLine($"{name}: {Describe(result.Outputs)}");
                }
                else
                {
                    Console.WriteLine($"{name}: rejected by the node ({result.Error})");
                }
            }
        }
        catch (SdkFfiException ex)
        {
            Console.Error.WriteLine($"Failed to call view functions: {ex.Message}");
            Environment.Exit(1);
        }
    }
}
