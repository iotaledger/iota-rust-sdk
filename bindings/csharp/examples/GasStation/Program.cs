// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();
        var gasStationUrl = "http://0.0.0.0:9527";
        var gasStationAuthToken = "test";
        var keypair = Ed25519PrivateKey.Random();
        var sender = keypair.PublicKey().DeriveAddress();
        var signer = TransactionSigner.FromEd25519(keypair);

        var builder = client.TransactionBuilder(sender);

        builder.MoveCall(
            Address.Std(),
            new Identifier("u64"),
            new Identifier("sqrt"),
            new[] { PtbArgument.U64(64) }
        );

        var headers = new Dictionary<string, string[]>
        {
            { "Authorization", new[] { $"Bearer {gasStationAuthToken}" } }
        };

        builder.GasStationSponsor(gasStationUrl, null, headers);

        var res = await builder.Execute(signer);

        Console.WriteLine(res);
        Console.WriteLine("Sponsored transaction was successful!");
    }
}
