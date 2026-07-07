// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        try
        {
            var client = GrpcClient.NewTestnet();

            var info = await client.GetServiceInfo();
            Console.WriteLine($"Chain ID: {info.ChainId}");
            Console.WriteLine($"Epoch: {info.Epoch}");
            Console.WriteLine($"Checkpoint height: {info.CheckpointHeight}");

            var gasPrice = await client.GetReferenceGasPrice();
            Console.WriteLine($"Reference gas price: {gasPrice}");
        }
        catch (SdkFfiException ex)
        {
            Console.Error.WriteLine($"Failed to get service info: {ex.Message}");
            Environment.Exit(1);
        }
    }
}
