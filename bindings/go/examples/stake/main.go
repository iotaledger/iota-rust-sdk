// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func addrFromHex(hex string) *iota_sdk.Address {
	address, err := iota_sdk.AddressFromHex(hex)
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	return address
}

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()

	myAddress := addrFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

	validators, err := client.ActiveValidators(nil, nil)
	if err != nil {
		log.Fatalf("Failed to get active validators: %v", err)
	}

	if len(validators.Data) == 0 {
		log.Fatal("No validators found")
	}
	validator := validators.Data[0]

	var validatorName string
	if validator.Name == nil {
		validatorName = "with no name"
	} else {
		validatorName = *validator.Name
	}
	log.Printf("Staking to validator %v", validatorName)

	builder := client.TransactionBuilder(myAddress)

	builder.Stake(iota_sdk.PtbArgumentU64(1000000000), validator.Address)

	res, err := builder.DryRun(false)
	if err != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to stake: %v", *res.Error)
	}

	log.Print("Stake dry run was successful!")
}
