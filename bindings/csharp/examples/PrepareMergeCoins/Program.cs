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
            throw new Exception("sender has no coins to merge");
        }
        if (coins.data.Length < 2)
        {
            throw new Exception("sender has only one coin, need two to merge");
        }
        var coin0 = PtbArgument.ObjectId(coins.data[0].Id());
        var coin1 = PtbArgument.ObjectId(coins.data[1].Id());

        var builder = new TransactionBuilder(sender).WithClient(client);

        builder.MergeCoins(coin0, new[] { coin1 });

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTx(txn);

        if (res.error != null)
        {
            throw new Exception($"Failed to merge coins: {res.error}");
        }

        Console.WriteLine("Merge coins dry run was successful!");
    }
}
