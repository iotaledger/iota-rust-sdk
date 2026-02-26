// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

using IotaSdk;

class Program
{
    static void Main(string[] args)
    {
        var mnemonic = Iota.GenerateMnemonic(null);
        Console.WriteLine($"24 word mnemonic: {mnemonic}");

        var wordCount = MnemonicLength.Words12;
        mnemonic = Iota.GenerateMnemonic(wordCount);
        Console.WriteLine($"12 word mnemonic: {mnemonic}");
    }
}
