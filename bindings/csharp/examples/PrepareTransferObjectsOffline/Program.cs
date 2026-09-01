// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var fromAddress = Address.FromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151");
        var toAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var objIds = new[]
        {
            ObjectId.FromHex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db"),
            ObjectId.FromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc"),
            ObjectId.FromHex("0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2")
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

        var gasCoinId = ObjectId.FromHex("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db");
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

        var res = await client.DryRunTransaction(txn);

        if (res.Error != null)
        {
            throw new Exception($"Failed to transfer objects: {res.Error}");
        }

        Console.WriteLine("Transfer objects dry run was successful!");
    }
}
