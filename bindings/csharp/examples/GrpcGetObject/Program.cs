// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GrpcClient.NewTestnet();

        var objectId = ObjectId.FromHex("0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755");

        // `Objects` is batched: it takes a list of ids and returns the objects in
        // the same order. The default read mask returns the reference and the
        // BCS-decoded object; pass `readMask: new[] { ObjectField.Reference }` to
        // skip the object.
        var obj = (await client.Objects(new[] { objectId }))[0].Object
            ?? throw new InvalidOperationException("Object not included in the response");

        Console.WriteLine($"Object ID: {obj.Id().ToHex()}");
        Console.WriteLine($"Version: {obj.Version()}");
        Console.WriteLine($"Previous transaction: {obj.PreviousTransaction().ToBase58()}");
        Console.WriteLine($"Owner: {obj.Owner()}");
        Console.WriteLine($"Storage rebate: {obj.StorageRebate()}");
        Console.WriteLine($"Type: {obj.ObjectType()}");
        Console.WriteLine($"BCS bytes: {Iota.HexEncode(obj.AsStruct().Contents)}");
    }
}
