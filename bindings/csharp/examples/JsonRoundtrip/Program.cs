// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example demonstrates how to convert a Transaction to and from JSON.
// A similar roundtrip can be done for other types as well.

using IotaSdk;

class Program
{
    static void Main(string[] args)
    {
        var txBytesBase64 = "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA=";

        var transaction = Transaction.FromBase64(txBytesBase64);

        var json = transaction.ToJson();
        Console.WriteLine($"Transaction as JSON:\n{json}");

        var parsedTransaction = Transaction.FromJson(json);
        Console.WriteLine($"Parsed transaction back from JSON: {parsedTransaction}");
    }
}
