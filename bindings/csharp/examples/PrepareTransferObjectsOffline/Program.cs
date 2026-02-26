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

        var objIds = new[]
        {
            ObjectId.FromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"),
            ObjectId.FromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"),
            ObjectId.FromHex("0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9")
        };

        var objsToTransfer = new List<PtbArgument>();
        foreach (var objId in objIds)
        {
            var obj = await client.Object(objId, null);
            if (obj == null)
            {
                throw new Exception($"Missing object: {objId.ToHex()}");
            }
            objsToTransfer.Add(PtbArgument.ObjectRef(obj.ObjectRef()));
        }

        var gasCoinId = ObjectId.FromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699");
        var gasCoin = await client.Object(gasCoinId, null);
        if (gasCoin == null)
        {
            throw new Exception($"Missing gas coin: {gasCoinId.ToHex()}");
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

        var res = await client.DryRunTx(txn);

        if (res.error != null)
        {
            throw new Exception($"Failed to transfer objects: {res.error}");
        }

        Console.WriteLine("Transfer objects dry run was successful!");
    }
}
