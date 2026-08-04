// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();
        var filter = new ObjectFilter(TypeTag: "0x2::coin::Coin<0x2::iota::IOTA>");

        var coins = await client.Objects(filter);

        if (coins.Data.Length == 0)
        {
            Console.WriteLine("No IOTA coin objects found");
        }
        else
        {
            Console.WriteLine("IOTA coin object IDs:");
            foreach (var coin in coins.Data)
            {
                Console.WriteLine(coin.Id().ToHex());
            }
        }
    }
}
