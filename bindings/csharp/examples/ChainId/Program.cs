// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        try
        {
            var chainId = await client.ChainId();
            Console.WriteLine($"Chain ID: {chainId}");
        }
        catch (SdkFfiException ex)
        {
            Console.Error.WriteLine($"Failed to get chain ID: {ex.Message}");
            Environment.Exit(1);
        }
    }
}
