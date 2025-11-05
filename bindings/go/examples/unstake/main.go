// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	stakedIotaType := sdk.StructTagNewStakedIota().String()
	stakedIotas, err := client.Objects(&sdk.ObjectFilter{TypeTag: &stakedIotaType}, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get staked iota: %v", err)
	}
	if len(stakedIotas.Data) == 0 {
		log.Fatal("No staked iota objects found")
	}
	stakedIota := stakedIotas.Data[0]

	builder := sdk.NewTransactionBuilder(stakedIota.Owner().AsAddress()).WithClient(client)
	builder.Unstake(sdk.PtbArgumentObjectId(stakedIota.ObjectId()))

	res, err := builder.DryRun(false)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to unstake: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to unstake: %v", *res.Error)
	}

	log.Print("Unstake dry run was successful!")
}
