// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var sender = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        var coinId = ObjectId.FromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc");

        var builder = client.TransactionBuilder(sender);

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

        if (res.Error != null)
        {
            throw new Exception($"Failed to split coins: {res.Error}");
        }

        Console.WriteLine("Split coins dry run was successful!");
    }
}
