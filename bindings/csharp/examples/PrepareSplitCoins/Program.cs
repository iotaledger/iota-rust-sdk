// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var sender = Address.FromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522");

        await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(sender, client);

        var coins = await client.Coins(sender, null, null);
        if (coins.data.Length == 0)
        {
            throw new Exception("sender has no coins");
        }
        var coinId = coins.data[0].Id();

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
