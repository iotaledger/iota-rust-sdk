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
        if (coins.data.Length < 3)
        {
            throw new Exception("sender does not own at least 3 coin objects to transfer");
        }
        var objsToTransfer = new[]
        {
            PtbArgument.ObjectId(coins.data[0].Id()),
            PtbArgument.ObjectId(coins.data[1].Id()),
            PtbArgument.ObjectId(coins.data[2].Id())
        };

        var builder = new TransactionBuilder(fromAddress).WithClient(client);
        builder.TransferObjects(toAddress, objsToTransfer);

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTx(txn);

        if (res.error != null)
        {
            throw new Exception($"Failed to transfer objects: {res.error}");
        }

        Console.WriteLine("Transfer objects dry run was successful!");
    }
}
