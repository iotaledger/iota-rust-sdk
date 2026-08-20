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

        var builder = client.TransactionBuilder(sender);

        builder.SplitCoins(PtbArgument.ObjectId(coinId), amounts.ToArray(), labels.ToArray());

        for (int i = 0; i < recipients.Length; i++)
        {
            builder.TransferObjects(Address.FromHex(recipients[i].Item1), new[] { PtbArgument.Assigned(labels[i]) });
        }

        var txn = await builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTx(txn);

        if (res.Error != null)
        {
            throw new Exception($"Failed to send IOTA: {res.Error}");
        }

        Console.WriteLine("Send IOTA dry run was successful!");
    }
}
