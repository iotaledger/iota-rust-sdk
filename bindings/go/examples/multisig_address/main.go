// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	recipientAddress, err := iota_sdk.AddressFromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")
	if err != nil {
		log.Fatalf("Failed to parse recipient address: %v", err)
	}

	signer1, err := iota_sdk.NewEd25519PrivateKey(make([]byte, 32))
	if err != nil {
		log.Fatalf("Failed to create signer1: %v", err)
	}
	signer2Bytes := make([]byte, 32)
	signer2Bytes[0] = 1
	signer2, err := iota_sdk.NewEd25519PrivateKey(signer2Bytes)
	if err != nil {
		log.Fatalf("Failed to create signer2: %v", err)
	}

	simple1 := iota_sdk.SimpleKeypairFromEd25519(signer1)
	simple2 := iota_sdk.SimpleKeypairFromEd25519(signer2)

	committee := iota_sdk.NewMultisigCommittee(
		[]*iota_sdk.MultisigMember{
			iota_sdk.NewMultisigMember(simple1.PublicKey(), 1),
			iota_sdk.NewMultisigMember(simple2.PublicKey(), 1),
		},
		2,
	)

	if !committee.IsValid() {
		log.Fatalf("Multisig committee is invalid")
	}

	multisigAddress := committee.DeriveAddress()
	log.Printf("Multisig sender address: %s", multisigAddress.ToHex())

	client := iota_sdk.GraphQlClientNewLocalnet()

	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWaitForFinalized(multisigAddress, client)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	builder := iota_sdk.NewTransactionBuilder(multisigAddress).WithClient(client)
	builder.SendIota(recipientAddress, iota_sdk.PtbArgumentU64(1000))
	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to build transaction: %v", err)
	}

	dryRunResult, err := client.DryRunTx(txn, false)
	if err != nil {
		log.Fatalf("Failed to dry run: %v", err)
	}
	if dryRunResult.Error != nil {
		log.Fatalf("Dry run failed: %s", *dryRunResult.Error)
	}

	sig1, err := simple1.SignTransaction(txn)
	if err != nil {
		log.Fatalf("Failed to sign with signer1: %v", err)
	}
	sig2, err := simple2.SignTransaction(txn)
	if err != nil {
		log.Fatalf("Failed to sign with signer2: %v", err)
	}

	aggregator := iota_sdk.MultisigAggregatorNewWithTransaction(committee, txn)
	aggregator, err = aggregator.WithSignature(sig1)
	if err != nil {
		log.Fatalf("Failed to add signer1 signature: %v", err)
	}
	aggregator, err = aggregator.WithSignature(sig2)
	if err != nil {
		log.Fatalf("Failed to add signer2 signature: %v", err)
	}

	multisigSig, err := aggregator.Finish()
	if err != nil {
		log.Fatalf("Failed to build multisig signature: %v", err)
	}

	userSig := iota_sdk.UserSignatureNewMultisig(multisigSig)
	effects, err := client.ExecuteTx([]*iota_sdk.UserSignature{userSig}, txn, nil)
	if err != nil {
		log.Fatalf("Failed to execute transaction: %v", err)
	}

	log.Printf("Digest: %s", iota_sdk.HexEncode((*effects).Digest().ToBytes()))
	log.Printf("Transaction status: %v", (*effects).AsV1().Status)
	log.Printf("Effects: %+v", (*effects).AsV1())
}
