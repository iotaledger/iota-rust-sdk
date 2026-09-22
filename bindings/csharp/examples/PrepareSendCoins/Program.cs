// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var fromAddress = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");
        var toAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var coinId = PtbArgument.ObjectIdFromHex("0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2");

        var builder = client.TransactionBuilder(fromAddress);

        builder.SendCoins(new[] { coinId }, toAddress, PtbArgument.U64(50000000000));

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await builder.DryRun(false);

        if (res.Error != null)
        {
            throw new Exception($"Failed to send coins: {res.Error}");
        }

        Console.WriteLine("Send coins dry run was successful!");
    }
}
