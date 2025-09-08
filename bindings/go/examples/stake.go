// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func isNilError(err error) bool {
	if sdkErr, ok := err.(*sdk.SdkFfiError); ok {
		return sdkErr == nil
	}
	return false
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	myAddress, err := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	validators, err := client.ActiveValidators(nil, &sdk.PaginationFilter{Direction: sdk.DirectionForward})
	if !isNilError(err) {
		log.Fatalf("Failed to get active validators: %v", err)
	}

	if len(validators.Data) == 0 {
		log.Fatal("No validators found")
	}
	validator := validators.Data[0]

	coinObjId, err := sdk.ObjectIdFromHex("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	coin, err := client.Object(coinObjId, nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get coin: %v", err)
	}

	gasCoinObjId, err := sdk.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	gasCoin, err := client.Object(gasCoinObjId, nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get gas coin: %v", err)
	}

	iotaSystemAddress, err := sdk.AddressFromHex("0x3")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	iotaSystemId, err := sdk.ObjectIdFromHex("0x5")
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}

	iotaSystemModule, err := sdk.NewIdentifier("iota_system")
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}

	requestAddStakeFn, err := sdk.NewIdentifier("request_add_stake")
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}

	builder := sdk.NewTransactionBuilder()
	inputs := []*sdk.Argument{
		builder.Input(sdk.UnresolvedInputNewShared(iotaSystemId, 1, true)),
		builder.Input(sdk.UnresolvedInputFromObject(*coin).WithOwnedKind()),
		builder.Input(sdk.UnresolvedInputNewPure(validator.Address.ToBytes())),
	}
	builder.MoveCall(
		sdk.Function{
			Package: iotaSystemAddress,
			Module: iotaSystemModule,
			Function: requestAddStakeFn,
		},
		inputs,
	)
	builder.SetSender(myAddress)
	builder.SetGasBudget(50000000)
	gasPrice, err := client.ReferenceGasPrice(nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	builder.SetGasPrice(*gasPrice)
	builder.AddGasObjects([]*sdk.UnresolvedInput{sdk.UnresolvedInputFromObject(*gasCoin).WithOwnedKind()})

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	res, err := client.DryRunTx(txn, nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get gas price: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to stake: %v", *res.Error)
	}

	log.Print("Successfully staked!")
}
