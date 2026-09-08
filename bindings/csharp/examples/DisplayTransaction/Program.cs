// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// This example demonstrates how to print types as human-readable text
// with the `ToDisplayString()` method.

using IotaSdk;

class Program
{
    static void Main(string[] args)
    {
        // A sample transaction in base64 format
        var txBytesBase64 = "AAACACAAAKSQS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA=";

        var transaction = Transaction.FromBase64(txBytesBase64);
        Console.WriteLine(transaction.ToDisplayString());

        Console.WriteLine(transaction.GasPayment().ToDisplayString());
    }
}
