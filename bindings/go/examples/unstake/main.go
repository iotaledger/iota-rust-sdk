// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	stakedIotaType := "0x3::staking_pool::StakedIota"
	stakedIotas, err := client.Objects(&sdk.ObjectFilter{TypeTag: &stakedIotaType}, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get staked iota: %v", err)
	}
	if len(stakedIotas.Data) == 0 {
		log.Fatal("No staked iota objects found")
	}
	stakedIota := stakedIotas.Data[0]

	gasCoinType := sdk.StructTagGasCoin().String()
	gasCoins, err := client.Objects(&sdk.ObjectFilter{TypeTag: &gasCoinType, Owner: stakedIota.Owner().AsAddressOpt()}, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas coin: %v", err)
	}
	if len(gasCoins.Data) == 0 {
		log.Fatal("No gas coins found")
	}
	gasCoin := gasCoins.Data[0]

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

	requestAddStakeFn, err := sdk.NewIdentifier("request_withdraw_stake")
	if err != nil {
		log.Fatalf("Failed to parse identifier: %v", err)
	}

	builder := sdk.NewTransactionBuilder()
	inputs := []*sdk.Argument{
		builder.Input(sdk.UnresolvedInputNewShared(iotaSystemId, 1, true)),
		builder.Input(sdk.UnresolvedInputFromObject(stakedIota).WithOwnedKind()),
	}
	builder.MoveCall(
		sdk.Function{
			Package:  iotaSystemAddress,
			Module:   iotaSystemModule,
			Function: requestAddStakeFn,
			TypeArgs: []*sdk.TypeTag{},
		},
		inputs,
	)
	builder.SetSender(gasCoin.Owner().AsAddress())
	builder.SetGasBudget(50000000)
	gasPrice, err := client.ReferenceGasPrice(nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	builder.SetGasPrice(*gasPrice)
	builder.AddGasObjects([]*sdk.UnresolvedInput{sdk.UnresolvedInputFromObject(gasCoin).WithOwnedKind()})

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	res, err := client.DryRunTx(txn, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to unstake: %v", *res.Error)
	}

	log.Print("Unstake dry run was successful!")
}
