// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();
        var accountId = await SetupAccount(client);
        var fromAddress = accountId.ToAddress();
        var toAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var faucet = FaucetClient.NewLocalnet();
        var faucetReceipt = await faucet.RequestAndWaitForFinalized(fromAddress, client);
        if (faucetReceipt == null)
            throw new Exception("Failed to request coins from faucet");

        var builder = new TransactionBuilder(fromAddress).WithClient(client);
        builder.SendIota(toAddress, PtbArgument.U64(5000000000));

        var moveAuthenticator = await new MoveAuthenticatorBuilder(
            accountId,
            new[] { PtbArgument.String("hello"), PtbArgument.Shared(ObjectId.Clock()) },
            new TypeTag[] { }
        ).Finish(client);

        var signer = TransactionSigner.FromMoveAuthenticator(moveAuthenticator);
        var effects = await builder.Execute(signer, WaitForTx.Finalized);

        Console.WriteLine($"Sending IOTA via abstract account: {effects.AsV1().Status}");
    }

    static async Task<ObjectId> SetupAccount(GraphQlClient client)
    {
        var PRECOMPILED_PACKAGE = "{\"modules\":[\"oRzrCwYAAAALAQAUAhQmAzorBGUGBWtPB7oBwAII+gNgBtoECRDjBCoKjQULDJgFQgAJAgkCCwINAg4CFgIXAhoCGwEKAAEMAAAAAgACAgIAAwMHAQgBBAQIAAUIBAAGBQgACAcCAAkGBwAAEwABAAAUAgEAAAwDAQABDwsBAQgDEAkKAQgFFQQFAAcYBwEBDAkZDA0ABgYEBgMGAggBBwgHAAQIAAYIBggICAgFBggACAgGCAQGCAIGCAcBBwgHAQgFAQgAAQkAAQsDAQgAAwYIBggICAgBCwMBCQACCQALAwEJAAEKAgEICAdBQ0NPVU5UB0FjY291bnQLQXV0aENvbnRleHQaQXV0aGVudGljYXRvckZ1bmN0aW9uUmVmVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlFmF1dGhlbnRpY2F0b3JfZnVuY3Rpb24FY2xvY2sRY3JlYXRlX2FjY291bnRfdjEbY3JlYXRlX2F1dGhfZnVuY3Rpb25fcmVmX3YxC2R1bW15X2ZpZWxkAmlkBGluaXQJbGlua19hdXRoA25ldwZvYmplY3QQcGFja2FnZV9tZXRhZGF0YRNwdWJsaWNfc2hhcmVfb2JqZWN0BnN0cmluZwh0cmFuc2Zlcgp0eF9jb250ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCgIGBWhlbGxvDmlvdGE6Om1ldGFkYXRhGgEAAAAAAAAAEQEMYXV0aGVudGljYXRlAQABAAIBEggFAQIBEQEAAAAAAQULAREFEgA4AAIBAQAACAkLAQsCCwM4AQwECwALBDgCAgIBAAABCQsBBwARByEEBgUIBgAAAAAAAAAAJwIA\"],\"dependencies\":[\"0x0000000000000000000000000000000000000000000000000000000000000002\",\"0x0000000000000000000000000000000000000000000000000000000000000001\"],\"digest\":[236,68,86,252,91,28,224,206,146,112,120,93,47,52,14,168,169,132,252,75,45,104,10,116,171,91,155,100,66,111,66,147]}";

        var packageData = MovePackageData.FromJson(PRECOMPILED_PACKAGE);
        var privateKey = Ed25519PrivateKey.Generate();
        var sender = privateKey.PublicKey().DeriveAddress();

        var faucet = FaucetClient.NewLocalnet();
        var faucetReceipt = await faucet.RequestAndWaitForFinalized(sender, client);
        if (faucetReceipt == null)
            throw new Exception("Failed to request coins from faucet");

        var builder = new TransactionBuilder(sender).WithClient(client);
        builder.PublishPackage(packageData, "upgrade_cap");
        builder.TransferObjects(sender, new[] { PtbArgument.Assigned("upgrade_cap") });

        var txSigner = TransactionSigner.FromEd25519(privateKey);
        var effects = await builder.Execute(txSigner, WaitForTx.Finalized);

        Console.WriteLine($"Publishing package: {effects.AsV1().Status}\n");

        ObjectId? packageId = null;
        ObjectId? packageMetadataId = null;
        ObjectId? accountId = null;

        foreach (var changedObj in effects.AsV1().ChangedObjects)
        {
            if (changedObj.OutputState is ObjectOut.PackageWrite)
            {
                packageId = changedObj.ObjectId;
            }
            else if (changedObj.OutputState is ObjectOut.ObjectWrite)
            {
                var objectId = changedObj.ObjectId;
                var obj = await client.Object(objectId, null);
                if (obj != null)
                {
                    var typeName = obj.AsStruct().StructType.Name().AsStr();
                    if (typeName == "PackageMetadataV1")
                        packageMetadataId = objectId;
                    if (typeName == "Account")
                        accountId = objectId;
                }
            }
        }

        if (packageId == null) throw new Exception("Missing package id");
        if (packageMetadataId == null) throw new Exception("Missing package metadata id");
        if (accountId == null) throw new Exception("Missing account id");

        Console.WriteLine($"Package ID: {packageId.ToHex()}");
        Console.WriteLine($"PackageMetadataV1 ID: {packageMetadataId.ToHex()}");
        Console.WriteLine($"Account ID: {accountId.ToHex()}\n");

        var builder2 = new TransactionBuilder(sender).WithClient(client);
        builder2.MoveCall(
            packageId.ToAddress(),
            new Identifier("account"),
            new Identifier("link_auth"),
            new[]
            {
                PtbArgument.SharedMut(accountId),
                PtbArgument.ObjectId(packageMetadataId),
                PtbArgument.String("account"),
                PtbArgument.String("authenticate")
            }
        );

        var effects2 = await builder2.Execute(txSigner, WaitForTx.Finalized);
        Console.WriteLine($"Linking account to authenticate method: {effects2.AsV1().Status}\n");

        return accountId;
    }
}