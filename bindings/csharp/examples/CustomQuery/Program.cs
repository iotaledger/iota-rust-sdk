// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json;
using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var client = GraphQlClient.NewDevnet();

        var queryEpochDataStr = @"
        query MyQuery($id: UInt53) {
            epoch(id: $id) {
                epochId
                referenceGasPrice
                totalGasFees
                totalCheckpoints
                totalTransactions
            }
        }";
        var queryEpochData = new Query(queryEpochDataStr, null);
        var res1 = await client.RunQuery(queryEpochData);
        Console.WriteLine(res1);

        var variables = JsonSerializer.Serialize(new { id = 1 });
        var queryEpochDataWithVariables = new Query(queryEpochDataStr, variables);
        var res2 = await client.RunQuery(queryEpochDataWithVariables);
        Console.WriteLine(res2);

        var queryChainIdStr = @"
        query MyQuery {
            chainIdentifier
        }";
        var queryChainId = new Query(queryChainIdStr, null);
        var res3 = await client.RunQuery(queryChainId);
        Console.WriteLine(res3);
    }
}
