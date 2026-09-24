// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    const ulong HowMany = 5;

    static async Task Main(string[] args)
    {
        var client = GrpcClient.NewLocalnet();

        // Pick a starting point a few checkpoints behind head so the example
        // returns promptly instead of waiting on new blocks.
        var head = (await client.CheckpointLatest()).SequenceNumber;
        var start = head >= HowMany - 1 ? head - (HowMany - 1) : 0;
        var end = head;

        // Only ask for the summary — keeps the message small. Pass null (or
        // compose more fields) to pull more data per checkpoint.
        var stream = await client.CheckpointsStream(start, end, readMask: new[] { CheckpointResponseField.CheckpointSummary });

        Console.WriteLine($"Streaming checkpoints {start}..={end}");
        CheckpointResponse? checkpoint;
        while ((checkpoint = await stream.Next()) != null)
        {
            var summary = checkpoint.Summary
                ?? throw new InvalidOperationException($"Checkpoint {checkpoint.SequenceNumber} has no summary");
            Console.WriteLine(
                $"  cp {checkpoint.SequenceNumber,6}  epoch {summary.Epoch(),3}  "
                    + $"txs {summary.NetworkTotalTransactions(),4}  ts {summary.TimestampMs()}");
        }
    }
}
