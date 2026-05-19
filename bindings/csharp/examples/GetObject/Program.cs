// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewLocalnet();

        var address = Address.FromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522");
        await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(address, client);

        var coins = await client.Coins(address, null, null);
        if (coins.data.Length == 0)
        {
            throw new Exception("address has no coins after faucet request");
        }
        var objectId = coins.data[0].Id();

        var obj = await client.Object(objectId, null);
        if (obj == null)
        {
            throw new Exception("missing object");
        }

        Console.WriteLine($"Object ID: {obj.ObjectId().ToHex()}");
        Console.WriteLine($"Version: {obj.Version()}");
        Console.WriteLine($"Previous transaction: {obj.PreviousTransaction().ToBase58()}");
        Console.WriteLine($"Owner: {obj.Owner()}");
        Console.WriteLine($"Storage rebate: {obj.StorageRebate()}");
        Console.WriteLine($"Type: {obj.ObjectType()}");
        Console.WriteLine($"BCS bytes: {Iota.HexEncode(obj.AsStruct().contents)}");
    }
}
