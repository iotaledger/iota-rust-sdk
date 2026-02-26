// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();
        var sender = Address.FromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c");
        var coinId = ObjectId.FromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab");

        var recipients = new (string, ulong)[]
        {
            ("0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11", 1_000_000_000),
            ("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522", 2_000_000_000)
        };

        var amounts = new List<PtbArgument>();
        var labels = new List<string>();

        for (int i = 0; i < recipients.Length; i++)
        {
            amounts.Add(PtbArgument.U64(recipients[i].Item2));
            labels.Add($"coin{i}");
        }

        var builder = new TransactionBuilder(sender).WithClient(client);

        builder.SplitCoins(PtbArgument.ObjectId(coinId), amounts.ToArray(), labels.ToArray());

        for (int i = 0; i < recipients.Length; i++)
        {
            builder.TransferObjects(Address.FromHex(recipients[i].Item1), new[] { PtbArgument.Assigned(labels[i]) });
        }

        var txn = builder.Finish();

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
