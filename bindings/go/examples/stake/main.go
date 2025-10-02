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

	coinObjId, _ := sdk.ObjectIdFromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")

	gasCoinObjId, _ := sdk.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")

	iotaSystemAddress, _ := sdk.AddressFromHex("0x3")

	iotaSystemId, _ := sdk.ObjectIdFromHex("0x5")

	iotaSystemModule, _ := sdk.NewIdentifier("iota_system")

	requestAddStakeFn, _ := sdk.NewIdentifier("request_add_stake")

	builder := sdk.TransactionBuilderInit(myAddress, client)

	builder.MoveCall(
		iotaSystemAddress,
		iotaSystemModule,
		requestAddStakeFn,
		[]*sdk.PtbArgument{
			sdk.PtbArgumentSharedMut(iotaSystemId),
			sdk.PtbArgumentObjectId(coinObjId),
			sdk.PtbArgumentAddress(validator.Address),
		},
		nil,
		nil,
	)
	builder.Gas(gasCoinObjId).GasBudget(1000000000)

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to stake: %v", *res.Error)
	}

	log.Print("Stake dry run was successful!")
}
