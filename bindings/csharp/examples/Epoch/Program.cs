// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewTestnet();

        // Get current epoch
        var currentEpoch = await client.Epoch(null);
        if (currentEpoch == null)
        {
            throw new Exception("missing current epoch");
        }

        Console.WriteLine($"Current epoch: {currentEpoch.epochId}");
        Console.WriteLine($"Current epoch start time: {currentEpoch.startTimestamp}");

        // Get previous epoch
        var previousEpochId = currentEpoch.epochId - 1;
        var previousEpoch = await client.Epoch(previousEpochId);
        if (previousEpoch == null)
        {
            throw new Exception("missing previous epoch");
        }

        Console.WriteLine($"Previous epoch: {previousEpoch.epochId}");
        if (previousEpoch.totalStakeRewards != null)
        {
            Console.WriteLine($"Previous epoch stake rewards: {previousEpoch.totalStakeRewards}");
        }
    }
}
