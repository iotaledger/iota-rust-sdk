// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var privateKey = Ed25519PrivateKey.Random();
        var fromAddress = privateKey.PublicKey().DeriveAddress();
        var toAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var faucet = FaucetClient.NewLocalnet();
        await faucet.RequestAndWaitForFinalized(fromAddress, client);

        var coins = (await client.Objects(filter: new ObjectFilter(Owner: fromAddress))).Data;
        if (coins.Length == 0)
        {
            throw new Exception("No coins found");
        }
        var gasCoin = coins[0];
        var objsToTransfer = new List<PtbArgument>();
        foreach (var coin in coins.Skip(1))
        {
            objsToTransfer.Add(PtbArgument.ObjectRef(coin.ObjectRef()));
        }

        var gasPrice = await client.ReferenceGasPrice() ?? 100;

        var builder = new TransactionBuilder(fromAddress);
        builder.TransferObjects(toAddress, objsToTransfer.ToArray());
        builder.Gas(new[] { gasCoin.ObjectRef() })
               .GasPrice(gasPrice)
               .GasBudget(500000000);

        var txn = builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTransaction(txn);

        if (res.Error != null)
        {
            throw new Exception($"Failed to transfer objects: {res.Error}");
        }

        Console.WriteLine("Transfer objects dry run was successful!");
    }
}
