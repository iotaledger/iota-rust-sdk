// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var sender = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");
        var sponsor = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        var builder = client.TransactionBuilder(sender);

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
        if (res.Error != null)
        {
            throw new Exception($"Failed to send gas sponsor tx: {res.Error}");
        }

        Console.WriteLine("Gas sponsor tx dry run was successful!");
    }
}
