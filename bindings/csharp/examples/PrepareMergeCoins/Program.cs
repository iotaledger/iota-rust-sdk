// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var sender = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");

        var coin0 = PtbArgument.ObjectIdFromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc");
        var coin1 = PtbArgument.ObjectIdFromHex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db");

        var builder = new TransactionBuilder(sender).WithClient(client);

        builder.MergeCoins(coin0, new[] { coin1 });

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await builder.DryRun(false);

        if (res.Error != null)
        {
            throw new Exception($"Failed to merge coins: {res.Error}");
        }

        Console.WriteLine("Merge coins dry run was successful!");
    }
}
