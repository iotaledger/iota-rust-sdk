// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();
        var filter = new ObjectFilter(TypeTag: "0x3::staking_pool::StakedIota");

        var stakedIotas = await client.Objects(filter);

        if (stakedIotas.Data.Length == 0)
        {
            Console.WriteLine("No StakedIota objects found");
        }
        else
        {
            Console.WriteLine("StakedIota object IDs:");
            foreach (var stakedIota in stakedIotas.Data)
            {
                Console.WriteLine(stakedIota.Id().ToHex());
            }
        }
    }
}
