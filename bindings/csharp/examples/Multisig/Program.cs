// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// 2-of-3 Ed25519 multisig example.
//
// Derives 3 keypairs from a mnemonic at indices 0, 1, 2, creates a multisig
// committee with threshold 2, funds the multisig address via faucet, builds
// a send_iota transaction, signs with only 2 of the 3 keys, aggregates,
// and executes.
//
// Requires a running localnet (`iota start --force-regenesis`).

using IotaSdk;

class Program
{
    static async Task Main(string[] args)
    {
        var mnemonic = "round attack kitchen wink winter music trip tiny nephew hire orange what";
        ulong amount = 1000;
        var recipientAddress = Address.FromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900");

        // 1. Derive 3 Ed25519 keypairs from mnemonic at indices 0, 1, 2
        var key0 = Ed25519PrivateKey.FromMnemonic(mnemonic, 0);
        var key1 = Ed25519PrivateKey.FromMnemonic(mnemonic, 1);
        var key2 = Ed25519PrivateKey.FromMnemonic(mnemonic, 2);

        // 2. Get MultisigMemberPublicKey via SimpleKeypair
        var kp0 = SimpleKeypair.FromEd25519(key0);
        var kp1 = SimpleKeypair.FromEd25519(key1);
        var kp2 = SimpleKeypair.FromEd25519(key2);

        // 3. Build multisig committee: threshold=2, each member weight=1
        var committee = new MultisigCommittee(
            new[] {
                new MultisigMember(kp0.PublicKey(), 1),
                new MultisigMember(kp1.PublicKey(), 1),
                new MultisigMember(kp2.PublicKey(), 1),
            },
            2
        );

        // 4. Derive multisig address
        var multisigAddress = committee.DeriveAddress();
        Console.WriteLine($"Multisig address: {multisigAddress.ToHex()}");

        var client = GraphQlClient.NewLocalnet();

        // 5. Fund the multisig address
        var faucet = FaucetClient.NewLocalnet();
        await faucet.RequestAndWaitForFinalized(multisigAddress, client);

        // 6. Build a send_iota transaction
        var builder = new TransactionBuilder(multisigAddress).WithClient(client);
        builder.SendIota(recipientAddress, PtbArgument.U64(amount));
        var txn = await builder.Finish();

        var dryRunResult = await client.DryRunTx(txn);
        if (dryRunResult.Error != null)
        {
            throw new Exception($"Dry run failed: {dryRunResult.Error}");
        }

        // 7. Sign with key0 and key1 (2-of-3 threshold)
        var sig0 = kp0.SignTransaction(txn);
        var sig1 = kp1.SignTransaction(txn);

        // 8. Aggregate signatures
        var aggregator = MultisigAggregator.NewWithTransaction(committee, txn);
        aggregator = aggregator.WithSignature(sig0);
        aggregator = aggregator.WithSignature(sig1);
        var aggSig = aggregator.Finish();

        // 9. Execute
        var userSignature = UserSignature.NewMultisig(aggSig);
        var effects = await client.ExecuteTx(new[] { userSignature }, txn);

        Console.WriteLine($"Digest: {Iota.HexEncode(effects.Digest().ToBytes())}");
        Console.WriteLine($"Transaction status: {effects.AsV1().Status}");
        Console.WriteLine($"Effects: {effects.AsV1()}");
    }
}
