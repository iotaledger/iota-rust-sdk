// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        var sender = Address.FromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c");

        var coin0 = PtbArgument.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab");
        var coin1 = PtbArgument.ObjectIdFromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699");

        var builder = new TransactionBuilder(sender).WithClient(client);

        builder.MergeCoins(coin0, new[] { coin1 });

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await builder.DryRun(false);

        if (res.error != null)
        {
            throw new Exception($"Failed to merge coins: {res.error}");
        }

        Console.WriteLine("Merge coins dry run was successful!");
    }
}
