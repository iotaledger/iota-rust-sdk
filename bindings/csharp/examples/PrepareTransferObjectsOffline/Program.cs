// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var fromAddress = Address.FromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522");
        var toAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        // Prefetch object refs and gas price online so the rest of the example
        // can be assembled offline.
        await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(fromAddress, client);
        var owned = await client.Objects(
            new ObjectFilter(owner: fromAddress, typeTag: "0x2::coin::Coin<0x2::iota::IOTA>")
        );
        if (owned.data.Length == 0)
        {
            throw new Exception("sender has no coins");
        }
        if (owned.data.Length < 4)
        {
            throw new Exception("sender does not own at least 4 coins (1 for gas + 3 to transfer)");
        }

        var gasCoinRef = owned.data[0].ObjectRef();
        var objsToTransfer = new[]
        {
            PtbArgument.ObjectRef(owned.data[1].ObjectRef()),
            PtbArgument.ObjectRef(owned.data[2].ObjectRef()),
            PtbArgument.ObjectRef(owned.data[3].ObjectRef())
        };

        var gasPrice = await client.ReferenceGasPrice() ?? 100;

        // From here on, no further network calls are made; the transaction is
        // assembled entirely from the prefetched object refs.
        var builder = new TransactionBuilder(fromAddress);
        builder.TransferObjects(toAddress, objsToTransfer);
        builder.Gas(new[] { gasCoinRef })
               .GasPrice(gasPrice)
               .GasBudget(500000000);

        var txn = builder.Finish();

        Console.WriteLine($"Signing Digest: {txn.SigningDigestHex()}");
        Console.WriteLine($"Txn Bytes: {txn.ToBase64()}");

        var res = await client.DryRunTx(txn);

        if (res.error != null)
        {
            throw new Exception($"Failed to transfer objects: {res.error}");
        }

        Console.WriteLine("Transfer objects dry run was successful!");
    }
}
