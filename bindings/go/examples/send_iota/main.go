// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()

	senderAddress, err := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
	if err != nil {
		log.Fatalf("Failed to parse sender address: %v", err)
	}
	gasCoinId, err := sdk.ObjectIdFromHex("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")
	if err != nil {
		log.Fatalf("Failed to parse gas coin id: %v", err)
	}

	recipients := []struct {
		address string
		amount  uint64
	}{
		{"0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11", 1_000_000_000},
		{"0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522", 2_000_000_000},
	}

	gasCoin, err := client.Object(gasCoinId, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas coin: %v", err)
	}

	builder := sdk.NewTransactionBuilder()

	// Prepare split amounts and recipient arguments
	var splitAmountArgs []*sdk.Argument
	var recipientArgs []*sdk.Argument
	for _, r := range recipients {
		// Convert uint64 to []byte (little endian)
		amountBytes := make([]byte, 8)
		for i := uint(0); i < 8; i++ {
			amountBytes[i] = byte(r.amount >> (8 * i))
		}
		splitAmountArgs = append(splitAmountArgs, builder.Input(sdk.UnresolvedInputNewPure(amountBytes)))
		recipientAddr, err := sdk.AddressFromHex(r.address)
		if err != nil {
			log.Fatalf("Failed to parse recipient address: %v", err)
		}
		recipientArgs = append(recipientArgs, builder.Input(sdk.UnresolvedInputNewPure(recipientAddr.ToBytes())))
	}

	// Split the gas coin into multiple coins
	splitCoinsResult := builder.SplitCoins(builder.Gas(), splitAmountArgs)

	// Transfer each split coin to its corresponding recipient
	for i, recipientArg := range recipientArgs {
		coinPtr := splitCoinsResult.GetNestedResult(uint16(i))
		if coinPtr == nil {
			log.Fatalf("Failed to get split coin result at index %d", i)
		}
		coinArg := *coinPtr
		builder.TransferObjects([]*sdk.Argument{coinArg}, recipientArg)
	}

	builder.SetSender(senderAddress)
	builder.SetGasBudget(50_000_000)
	gasPrice, err := client.ReferenceGasPrice(nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	builder.SetGasPrice(*gasPrice)
	builder.AddGasObjects([]*sdk.UnresolvedInput{sdk.UnresolvedInputFromObject(*gasCoin).WithOwnedKind()})

	txn, err := builder.Finish()
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	res, err := client.DryRunTx(txn, nil)
	if err.(*sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to dry run send IOTA: %v", err)
	}
	if res.Error != nil {
		log.Fatalf("Failed to send IOTA: %v", *res.Error)
	}
	log.Print("Send IOTA dry run was successful!")
}
