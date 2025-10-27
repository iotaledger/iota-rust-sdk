// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	myAddress, _ := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

	validators, err := client.ActiveValidators(nil, nil)
	if err.(*sdk.SdkFfiError) != nil {
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

	builder := sdk.TransactionBuilderInit(myAddress, client)

	builder.Stake(sdk.PtbArgumentU64(1000000000), validator.Address)

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to stake: %v", *res.Error)
	}

	log.Print("Stake dry run was successful!")
}
