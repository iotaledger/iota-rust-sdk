// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var sender = Address.Zero();
        var stdAddress = Address.Std();

        var builder = new TransactionBuilder(sender).WithClient(client);

        // Build a small chain of stdlib Move calls and extract the return value
        // from the final command via dry_run.
        builder.MoveCall(
            stdAddress,
            new Identifier("u64"),
            new Identifier("max"),
            new[] { PtbArgument.U64(100), PtbArgument.U64(200) },
            [],
            new[] { "max_value" }
        );

        builder.MoveCall(
            stdAddress,
            new Identifier("u64"),
            new Identifier("min"),
            new[] { PtbArgument.Assigned("max_value"), PtbArgument.U64(150) },
            [],
            new[] { "result" }
        );

        var res = await builder.DryRun(true);

        if (res.error != null)
        {
            throw new Exception($"Failed to dry-run: {res.error}");
        }

        if (res.results.Length > 0)
        {
            var lastEffect = res.results[res.results.Length - 1];
            if (lastEffect.returnValues.Length > 0)
            {
                var returnValue = lastEffect.returnValues[0];
                if (returnValue.typeTag.IsU64() && returnValue.bcs.Length == 8)
                {
                    var value = BitConverter.ToUInt64(returnValue.bcs, 0);
                    Console.WriteLine($"min(max(100, 200), 150) = {value}");
                }
                else
                {
                    Console.WriteLine("Failed to extract u64 from results");
                }
            }
            else
            {
                Console.WriteLine("Failed to extract u64 from results");
            }
        }
        else
        {
            Console.WriteLine("Failed to extract u64 from results");
        }
    }
}
