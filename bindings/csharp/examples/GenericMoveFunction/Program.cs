// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        var sender = Address.FromHex("0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e");

        var builder = new TransactionBuilder(sender).WithClient(client);

        var addr1 = Address.FromHex("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e");
        var addr2 = Address.FromHex("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3");

        builder.MoveCall(
            Address.Framework(),
            new Identifier("vec_map"),
            new Identifier("from_keys_values"),
            new[]
            {
                PtbArgument.AddressVec(new[] { addr1, addr2 }),
                PtbArgument.U64Vec(new[] { 10_000_000ul, 20_000_000ul })
            },
            new[]
            {
                TypeTag.NewAddress(),
                TypeTag.NewU64()
            },
            []
        );

        var res = await builder.DryRun(true);

        if (res.Error != null)
        {
            throw new Exception($"Failed to call generic Move function: {res.Error}");
        }

        Console.WriteLine("Successfully called generic Move function!");
    }
}
