// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	owner, err := iota_sdk.AddressFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

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
