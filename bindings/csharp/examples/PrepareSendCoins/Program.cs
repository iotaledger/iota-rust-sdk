// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var fromAddress = Address.FromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522");
        var toAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(fromAddress, client);

        var coins = await client.Coins(fromAddress, null, null);
        if (coins.data.Length == 0)
        {
            throw new Exception("sender has no coins");
        }
        var coinId = PtbArgument.ObjectId(coins.data[0].Id());

        var builder = new TransactionBuilder(fromAddress).WithClient(client);

        builder.SendCoins(new[] { coinId }, toAddress, PtbArgument.U64(50000000000));

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTx(txn);

        if (res.error != null)
        {
            throw new Exception($"Failed to send coins: {res.error}");
        }

        Console.WriteLine("Send coins dry run was successful!");
    }
}
