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

        var builder = new TransactionBuilder(fromAddress).WithClient(client);
        builder.SendIota(toAddress, PtbArgument.U64(5000000000));

        var txn = await builder.Build();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTx(txn);
        if (res.error != null)
        {
            throw new Exception($"Failed to send IOTA: {res.error}");
        }

        Console.WriteLine("Send IOTA dry run was successful!");
    }
}
