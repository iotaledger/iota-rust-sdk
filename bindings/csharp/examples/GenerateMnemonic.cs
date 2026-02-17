// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Milestone 1 translation of bindings/python/examples/generate_mnemonic.py.
// This file is scaffold-only until generated C# bindings are wired in.

using IotaSdk;

var mnemonic24 = Mnemonic.Generate();
Console.WriteLine($"24 word mnemonic: {mnemonic24}");

var mnemonic12 = Mnemonic.Generate(MnemonicLength.Words12);
Console.WriteLine($"12 word mnemonic: {mnemonic12}");
