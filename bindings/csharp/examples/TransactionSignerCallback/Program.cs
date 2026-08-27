// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class AsyncSigner : TransactionSignerFn
{
    private Ed25519PrivateKey _key;

    public AsyncSigner(Ed25519PrivateKey key)
    {
        _key = key;
    }

    public Task<TransactionSignerFnOutput> Sign(Transaction transaction)
    {
        var signature = _key.SignTransaction(transaction);
        return Task.FromResult(new TransactionSignerFnOutput(signature));
    }
}

class Program
{
    static async Task Main(string[] args)
    {
        ulong amount = 1000;
        var recipientAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var privateKey = new Ed25519PrivateKey(new byte[32]);
        var publicKey = privateKey.PublicKey();
        var senderAddress = publicKey.DeriveAddress();

        Console.WriteLine($"Sender address: {senderAddress.ToHex()}");

        var client = GraphQlClient.NewLocalnet();

        var faucet = FaucetClient.NewLocalnet();
        await faucet.RequestAndWaitForFinalized(senderAddress, client);

        var builder = client.TransactionBuilder(senderAddress);
        builder.SendIota(recipientAddress, PtbArgument.U64(amount));

        var signer = new TransactionSigner(new AsyncSigner(privateKey));
        var effects = await builder.Execute(signer, WaitForTx.Finalized);

        Console.WriteLine($"Digest: {Iota.HexEncode(effects.Digest().ToBytes())}");
        Console.WriteLine($"Transaction status: {effects.AsV1().Status()}");
        Console.WriteLine($"Effects: {effects.AsV1()}");
    }
}
