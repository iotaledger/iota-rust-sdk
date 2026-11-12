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

        var headers = new Dictionary<string, string[]>
        {
            { "Authorization", new[] { $"Bearer {gasStationAuthToken}" } }
        };

        var gasStation = new GasStation(gasStationUrl, null, headers);

        var builder = client.TransactionBuilder(sender);

        builder.MoveCall(
            Address.Std(),
            new Identifier("u64"),
            new Identifier("sqrt"),
            new[] { PtbArgument.U64(64) }
        );

        var res = await builder.ExecuteWithGasStation(gasStation, signer);

        Console.WriteLine(res);
        Console.WriteLine("Sponsored transaction was successful!");
    }
}
