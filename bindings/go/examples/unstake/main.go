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

	iotaSystemAddress, _ := sdk.AddressFromHex("0x3")

	iotaSystemId, _ := sdk.ObjectIdFromHex("0x5")

	iotaSystemModule, _ := sdk.NewIdentifier("iota_system")

	requestAddStakeFn, _ := sdk.NewIdentifier("request_withdraw_stake")

	builder := sdk.TransactionBuilderInit(gasCoin.Owner().AsAddress(), client)
	builder.MoveCall(
		iotaSystemAddress,
		iotaSystemModule,
		requestAddStakeFn,
		[]*sdk.PtbArgument{sdk.PtbArgumentSharedMut(iotaSystemId), sdk.PtbArgumentObjectId(stakedIota.ObjectId())},
		nil,
		nil,
	)

	builder.Gas(gasCoin.ObjectId())

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to unstake: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to unstake: %v", *res.Error)
	}

	log.Print("Unstake dry run was successful!")
}
