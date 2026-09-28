// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        // Amount to send in nanos
        ulong amount = 1000;
        var recipientAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var privateKey = new Ed25519PrivateKey(new byte[32]);
        var senderAddress = privateKey.PublicKey().DeriveAddress();
        Console.WriteLine($"Sender address: {senderAddress.ToHex()}");

        // Request funds from faucet (the faucet client relies on GraphQL to
        // await finalization)
        var faucet = FaucetClient.NewLocalnet();
        await faucet.RequestAndWaitForFinalized(senderAddress, GraphQlClient.NewLocalnet());

        var client = GrpcClient.NewLocalnet();

        // Resolve gas and build the transaction via gRPC
        var builder = new TransactionBuilder(senderAddress).WithGrpcClient(client);
        builder.SendIota(recipientAddress, PtbArgument.U64(amount));
        var txn = await builder.Finish();

        // Simulate first: the node runs the transaction without committing it.
        var simulated = await client.SimulateTransaction(txn);
        if (simulated.ExecutionError != null)
        {
            Console.WriteLine($"Simulation aborted: {simulated.ExecutionError.Source}");
        }
        else
        {
            Console.WriteLine($"Simulation succeeded: {simulated.CommandResults?.Length ?? 0} command result(s), suggested gas price {simulated.SuggestedGasPrice}");
        }

        var signature = privateKey.SignTransaction(txn);
        var signedTransaction = new SignedTransaction(txn, new[] { signature });

        var executed = await client.ExecuteTransaction(signedTransaction);

        Console.WriteLine($"Digest: {Iota.HexEncode(executed.Digest!.ToBytes())}");
        Console.WriteLine($"Transaction status: {executed.Effects!.AsV1().Status()}");
    }
}
