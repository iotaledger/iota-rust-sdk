// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        var fromAddress = Address.FromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c");
        var toAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var coinId = PtbArgument.ObjectIdFromHex("0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9");

        var builder = new TransactionBuilder(fromAddress).WithClient(client);

        builder.SendCoins(new[] { coinId }, toAddress, PtbArgument.U64(50000000000));

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await builder.DryRun(false);

        if (res.error != null)
        {
            throw new Exception($"Failed to send coins: {res.error}");
        }

        Console.WriteLine("Send coins dry run was successful!");
    }
}
