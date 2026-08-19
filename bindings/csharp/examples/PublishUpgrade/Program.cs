// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var packageDataJson = Environment.GetEnvironmentVariable("COMPILED_PACKAGE");
        if (packageDataJson == null)
        {
            Console.WriteLine("No compiled package found in env var. Using default.");
            packageDataJson = "{\"modules\":[\"oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA\"],\"dependencies\":[\"0x0000000000000000000000000000000000000000000000000000000000000002\",\"0x0000000000000000000000000000000000000000000000000000000000000001\"],\"digest\":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}";
        }
        else
        {
            Console.WriteLine("Using custom Move package found in env var.");
        }

        var packageData = MovePackageData.FromJson(packageDataJson);
        Console.WriteLine($"Modules: {packageData.Modules().Length}");
        Console.WriteLine($"Dependencies: {packageData.Dependencies().Length}");
        Console.WriteLine($"Digest: {packageData.Digest().ToBase58()}");

        var privateKey = Ed25519PrivateKey.Random();
        var sender = privateKey.PublicKey().DeriveAddress();
        Console.WriteLine($"Sender: {sender.ToHex()}");

        var client = GraphQlClient.NewLocalnet();

        var faucet = FaucetClient.NewLocalnet();
        var faucetReceipt = await faucet.RequestAndWaitForFinalized(sender, client);
        if (faucetReceipt == null)
            throw new Exception("Failed to request coins from faucet");

        var builder = new TransactionBuilder(sender).WithClient(client);
        builder.PublishPackage(packageData, "upgrade_cap");
        builder.TransferObjects(sender, new[] { PtbArgument.Assigned("upgrade_cap") });
        var tx = await builder.Finish();

        Console.WriteLine("> Publishing package (dry run):");
        var result = await client.DryRunTx(tx);
        if (result.Error != null)
            throw new Exception($"Dry run failed: {result.Error}");
        if (result.Effects == null)
            throw new Exception("Dry run failed: no effects");
        Console.WriteLine("Success");

        Console.WriteLine("> Publishing package:");
        var sig = privateKey.SignTransaction(tx);
        var effects = await client.ExecuteTx(new[] { sig }, tx, WaitForTx.Finalized);
        Console.WriteLine("Success");

        ObjectId? upgradeCap = null;
        ObjectId? packageId = null;
        foreach (var changedObj in effects.AsV1().ChangedObjects)
        {
            if (changedObj.OutputState is ObjectOut.ObjectWrite objWrite)
            {
                var objectId = changedObj.ObjectId;
                var obj = await client.Object(objectId, null);
                if (obj == null) throw new Exception($"Missing object {objectId.ToHex()}");

                if (obj.AsStruct().StructType.Equals(StructTag.NewUpgradeCap()))
                {
                    Console.WriteLine($"UpgradeCap: {objectId.ToHex()}");
                    Console.WriteLine($"UpgradeCapOwner: {objWrite.Owner.AsAddress().ToHex()}");
                    upgradeCap = objectId;
                }
            }
            else if (changedObj.OutputState is ObjectOut.PackageWrite pkgWrite)
            {
                packageId = changedObj.ObjectId;
                Console.WriteLine($"Package ID: {packageId.ToHex()}");
                Console.WriteLine($"Package version: {pkgWrite.Version}");
            }
        }

        if (upgradeCap == null) throw new Exception("Missing upgrade cap");
        if (packageId == null) throw new Exception("Missing package id");

        builder = new TransactionBuilder(sender).WithClient(client);

        builder.MoveCall(
            Address.Framework(),
            new Identifier("package"),
            new Identifier("authorize_upgrade"),
            new[] {
                PtbArgument.ObjectId(upgradeCap),
                PtbArgument.U8(UpgradePolicy.Compatible().AsU8()),
                PtbArgument.U8Vec(packageData.Digest().ToBytes())
            },
            [],
            new[] { "upgrade_ticket" }
        );

        builder.Upgrade(
            packageId,
            packageData,
            PtbArgument.Assigned("upgrade_ticket"),
            "upgrade_receipt"
        );

        builder.MoveCall(
            Address.Framework(),
            new Identifier("package"),
            new Identifier("commit_upgrade"),
            new[] {
                PtbArgument.ObjectId(upgradeCap),
                PtbArgument.Assigned("upgrade_receipt")
            }
        );

        tx = await builder.Finish();

        Console.WriteLine("> Upgrading package (dry run):");
        result = await client.DryRunTx(tx);
        if (result.Error != null)
            throw new Exception($"Dry run failed: {result.Error}");
        if (result.Effects == null)
            throw new Exception("Dry run failed: no effects");
        Console.WriteLine("Success");

        Console.WriteLine("> Upgrading package:");
        sig = privateKey.SignTransaction(tx);
        effects = await client.ExecuteTx(new[] { sig }, tx);
        Console.WriteLine("Success");

        foreach (var changedObj in effects.AsV1().ChangedObjects)
        {
            if (changedObj.OutputState is ObjectOut.PackageWrite pkgWrite2)
            {
                Console.WriteLine($"New Package ID: {changedObj.ObjectId.ToHex()}");
                Console.WriteLine($"New Package version: {pkgWrite2.Version}");
            }
        }
    }
}
