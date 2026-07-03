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

        Console.WriteLine($"Current epoch: {currentEpoch.EpochId}");
        Console.WriteLine($"Current epoch start time: {currentEpoch.StartTimestamp}");

        // Get previous epoch
        var previousEpochId = currentEpoch.EpochId - 1;
        var previousEpoch = await client.Epoch(previousEpochId);
        if (previousEpoch == null)
        {
            throw new Exception("missing previous epoch");
        }

        Console.WriteLine($"Previous epoch: {previousEpoch.EpochId}");
        if (previousEpoch.TotalStakeRewards != null)
        {
            Console.WriteLine($"Previous epoch stake rewards: {previousEpoch.TotalStakeRewards}");
        }
    }
}
