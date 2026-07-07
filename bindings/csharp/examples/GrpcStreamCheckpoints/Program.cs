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

            // Pick a small range of recent checkpoints to stream.
            var latest = await client.GetCheckpointLatest();
            var start = latest.SequenceNumber - 4;

            var stream = await client.StreamCheckpoints(start, latest.SequenceNumber);

            CheckpointResponse? checkpoint;
            while ((checkpoint = await stream.Next()) != null)
            {
                var summary = checkpoint.Summary!;
                Console.WriteLine(
                    $"Checkpoint {checkpoint.SequenceNumber}: epoch {summary.Epoch()}, "
                        + $"{summary.NetworkTotalTransactions()} total transactions, "
                        + $"timestamp {summary.TimestampMs()}");
            }
        }
        catch (SdkFfiException ex)
        {
            Console.Error.WriteLine($"Failed to stream checkpoints: {ex.Message}");
            Environment.Exit(1);
        }
    }
}
