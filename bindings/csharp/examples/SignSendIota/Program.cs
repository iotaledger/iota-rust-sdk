// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        ulong amount = 1000;
        var recipientAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var privateKeyBytes = new byte[32]; // All zeros
        var privateKey = new Ed25519PrivateKey(privateKeyBytes);
        var publicKey = privateKey.PublicKey();
        var senderAddress = publicKey.DeriveAddress();

        Console.WriteLine($"Sender address: {senderAddress.ToHex()}");

        var client = GraphQlClient.NewLocalnet();

        var faucet = FaucetClient.NewLocalnet();
        await faucet.RequestAndWaitForFinalized(senderAddress, client);

        var builder = client.TransactionBuilder(senderAddress);
        builder.SendIota(recipientAddress, PtbArgument.U64(amount));

        var txn = await builder.Finish();

        var dryRunResult = await client.DryRunTx(txn);
        if (dryRunResult.Error != null)
        {
            throw new Exception($"Dry run failed: {dryRunResult.Error}");
        }

        var signature = privateKey.TrySignSimple(txn.SigningDigest());
        var userSignature = UserSignature.NewSimple(signature);

        var effects = await client.ExecuteTx(new[] { userSignature }, txn);

        Console.WriteLine($"Digest: {Iota.HexEncode(effects.Digest().ToBytes())}");
        Console.WriteLine($"Transaction status: {effects.AsV1().Status}");
        Console.WriteLine($"Effects: {effects.AsV1()}");
    }
}
