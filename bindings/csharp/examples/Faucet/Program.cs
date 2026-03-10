// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var address = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");
        var faucetClient = FaucetClient.NewLocalnet();

        var faucetReceipt = await faucetClient.RequestAndWait(address);

        if (faucetReceipt != null)
        {
            Console.WriteLine("Faucet receipt:");
            foreach (var coin in faucetReceipt.sent)
            {
                Console.WriteLine($"  Coin ID: {coin.id.ToHex()}, Amount: {coin.amount}, Digest: {coin.transferTxDigest.ToBase58()}");
            }
        }
        else
        {
            Console.WriteLine("Faucet receipt: None");
        }
    }
}
