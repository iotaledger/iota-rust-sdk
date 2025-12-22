// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	stakedIotaType := iota_sdk.StructTagNewStakedIota().String()
	stakedIotas, err := client.Objects(&iota_sdk.ObjectFilter{TypeTag: &stakedIotaType}, nil)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get staked iota: %v", err)
	}
	if len(stakedIotas.Data) == 0 {
		log.Fatal("No staked iota objects found")
	}
	stakedIota := stakedIotas.Data[0]

	builder := iota_sdk.NewTransactionBuilder(stakedIota.Owner().AsAddress()).WithClient(client)
	builder.Unstake(iota_sdk.PtbArgumentObjectId(stakedIota.ObjectId()))

	res, err := builder.DryRun(false)
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to unstake: %v", err)
	}

	if res.Error != nil {
		log.Fatalf("Failed to unstake: %v", *res.Error)
	}

	log.Print("Unstake dry run was successful!")
}
