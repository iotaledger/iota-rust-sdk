// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Send IOTA from a Ledger device's address on a local network. Set
// LEDGER_SIMULATOR to use the Speculos emulator instead of a device.

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        // Amount to send in nanos
        ulong amount = 1000;
        var recipientAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        var ledger = Environment.GetEnvironmentVariable("LEDGER_SIMULATOR") != null
            ? Ledger.Speculos("127.0.0.1", 9999)
            : Ledger.NativeHid();
        await ledger.OpenApp();
        var signer = await ledger.Signer("m/44'/4218'/0'/0'/0'");
        var senderAddress = signer.Address();
        Console.WriteLine($"Sender address: {senderAddress}");

        var client = GraphQlClient.NewLocalnet();

        // Request funds from faucet
        await FaucetClient.NewLocalnet().RequestAndWaitForFinalized(senderAddress, client);

        var builder = client.TransactionBuilder(senderAddress);
        builder.SendIota(recipientAddress, PtbArgument.U64(amount));

        // The builder passes the signer the coins the transaction spends, so the
        // device shows the transfer instead of asking to blind-sign
        Console.WriteLine("Review and approve the transaction on the device");
        var effects = await builder.Execute(TransactionSigner.FromLedger(signer), WaitForTransaction.Finalized);
        Console.WriteLine($"Digest: {effects.Digest().ToBase58()}");
        Console.WriteLine($"Transaction status: {effects.AsV1().Status()}");
    }
}
