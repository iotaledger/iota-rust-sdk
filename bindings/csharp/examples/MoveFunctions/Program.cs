// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Threading.Tasks;
using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        var packageAddress = Address.FromHex("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f");

        var package = await client.Package(packageAddress);
        if (package == null)
        {
            throw new Exception("missing package");
        }

        foreach (var moduleId in package.Modules())
        {
            var module = await client.NormalizedMoveModule(packageAddress, moduleId.Key.AsStr());
            if (module == null)
            {
                Console.WriteLine($"module `{moduleId.Key.AsStr()}` not found");
                return;
            }
            if (module.functions != null)
            {
                Console.WriteLine($"Module: {moduleId.Key.AsStr()}");
                foreach (var fun in module.functions.nodes)
                {
                    Console.WriteLine($"- {fun.ToString()}");
                }
                Console.WriteLine();
            }
        }
    }
}
