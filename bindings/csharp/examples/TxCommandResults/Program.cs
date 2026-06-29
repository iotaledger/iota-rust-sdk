// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var sender = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        var builder = new TransactionBuilder(sender).WithClient(client);

        var packageAddr = Address.Std();
        var moduleName = new Identifier("u64");
        var functionName = new Identifier("max");

        builder.MoveCall(
            packageAddr,
            moduleName,
            functionName,
            new[] { PtbArgument.U64(0), PtbArgument.U64(1000) },
            [],
            new[] { "res0" }
        );

        builder.MoveCall(
            packageAddr,
            moduleName,
            functionName,
            new[] { PtbArgument.U64(1000), PtbArgument.U64(2000) },
            [],
            new[] { "res1" }
        );

        builder.SplitCoins(
            PtbArgument.Gas(),
            new[] { PtbArgument.Assigned("res0"), PtbArgument.Assigned("res1") },
            new[] { "coin0", "coin1" }
        );

        builder.TransferObjects(
            sender,
            new[] { PtbArgument.Assigned("coin0"), PtbArgument.Assigned("coin1") }
        );

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTx(txn);

        if (res.Error != null)
        {
            throw new Exception($"Failed to send tx: {res.Error}");
        }

        Console.WriteLine("Tx dry run was successful!");
    }
}
