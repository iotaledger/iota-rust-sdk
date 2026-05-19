// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var sender = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");
        var sponsor = Address.FromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522");

        await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(sponsor, client);

        var builder = new TransactionBuilder(sender).WithClient(client);

        var packageAddr = Address.Std();
        var moduleName = new Identifier("u8");
        var functionName = new Identifier("max");

        var argsList = new[]
        {
            PtbArgument.U8(0),
            PtbArgument.U8(1)
        };

        builder.MoveCall(packageAddr, moduleName, functionName, argsList);
        builder.Sponsor(sponsor);

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTx(txn);
        if (res.error != null)
        {
            throw new Exception($"Failed to send gas sponsor tx: {res.error}");
        }

        Console.WriteLine("Gas sponsor tx dry run was successful!");
    }
}
