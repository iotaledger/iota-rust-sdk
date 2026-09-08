// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()

	privateKey := iota_sdk.Ed25519PrivateKeyRandom()
	owner := privateKey.PublicKey().DeriveAddress()

	faucet := iota_sdk.FaucetClientNewLocalnet()
	if _, err := faucet.RequestAndWaitForFinalized(owner, client); err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
	}

	// Stake to get a StakedIota object that can be unstaked
	validators, err := client.ActiveValidators(nil, nil)
	if err != nil {
		log.Fatalf("Failed to get active validators: %v", err)
	}
	if len(validators.Data) == 0 {
		log.Fatal("No validators found")
	}
	validator := validators.Data[0]

	stakeBuilder := client.TransactionBuilder(owner)
	stakeBuilder.Stake(iota_sdk.PtbArgumentU64(1000000000), validator.Address)
	stakeTx, err := stakeBuilder.Finish()
	if err != nil {
		log.Fatalf("Failed to create stake transaction: %v", err)
	}
	signature, err := privateKey.TrySignSimple(stakeTx.SigningDigest())
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	waitFor := iota_sdk.WaitForTransactionFinalized
	if _, err := client.ExecuteTransaction([]*iota_sdk.UserSignature{iota_sdk.UserSignatureNewSimple(signature)}, stakeTx, &waitFor); err != nil {
		log.Fatalf("Failed to stake: %v", err)
	}

	// Unstake
	stakedIotaType := iota_sdk.StructTagNewStakedIota().String()
	stakedIotas, err := client.Objects(&iota_sdk.ObjectFilter{TypeTag: &stakedIotaType, Owner: &owner}, nil)
	if err != nil {
		log.Fatalf("Failed to get staked iota: %v", err)
	}
	if len(stakedIotas.Data) == 0 {
		log.Fatal("No staked iota objects found")
	}
	stakedIota := stakedIotas.Data[0]

	builder := client.TransactionBuilder(stakedIota.Owner().AsAddress())
	builder.Unstake(iota_sdk.PtbArgumentObjectId(stakedIota.Id()))

	res, err := builder.DryRun(false)
	if err != nil {
		log.Fatalf("Failed to unstake: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to unstake: %v", *res.Error)
	}

	log.Print("Unstake dry run was successful!")
}
