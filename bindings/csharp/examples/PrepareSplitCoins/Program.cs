// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        var sender = Address.FromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c");

        var coinId = ObjectId.FromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab");

        var builder = new TransactionBuilder(sender).WithClient(client);

        builder.SplitCoins(
            PtbArgument.ObjectId(coinId),
            new[] { PtbArgument.U64(1000), PtbArgument.U64(2000), PtbArgument.U64(3000) },
            new[] { "coin1", "coin2", "coin3" }
        )
        .TransferObjects(
            sender,
            new[] { PtbArgument.Assigned("coin1"), PtbArgument.Assigned("coin2"), PtbArgument.Assigned("coin3") }
        );

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await builder.DryRun(false);

        if (res.error != null)
        {
            throw new Exception($"Failed to split coins: {res.error}");
        }

        Console.WriteLine("Split coins dry run was successful!");
    }
}
