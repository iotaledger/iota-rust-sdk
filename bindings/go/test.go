package main

import (
	"fmt"
	"log"

	sdk "example.com/bindings/iota_sdk_ffi"
)

func isNilError(err error) bool {
	if sdkErr, ok := err.(*sdk.SdkFfiError); ok {
		return sdkErr == nil
	}
	return false
}

func main() {
	client := sdk.GraphQlClientNewDevnet()

	chainID, err := client.ChainId()
	if !isNilError(err) {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)

	address, err := sdk.AddressFromHex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	pagination := sdk.PaginationFilter{
		Direction: sdk.DirectionForward,
		Cursor:    nil,
		Limit:     nil,
	}

	coins, err := client.Coins(address, pagination, nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get coins: %v", err)
	}

	for _, coin := range coins.Data {
		fmt.Printf("ID = 0x%s Balance = %d\n", coin.Id().ToHex(), coin.Balance())
	}

	balance, err := client.Balance(address, nil)
	if !isNilError(err) {
		log.Fatalf("Failed to get balance: %v", err)
	}
	fmt.Printf("Total Balance = %d\n", balance)

	atCheckpoint := uint64(3)
	inputObject, err := sdk.ObjectIdFromHex("0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f")
	if err != nil {
		log.Fatalf("Failed to parse object ID: %v", err)
	}
	txFilter := sdk.TransactionsFilter{
		AtCheckpoint: &atCheckpoint,
		InputObject: &inputObject,
	}
	eventFilter := sdk.EventFilter{
		Sender: &address,
	}

	_ = txFilter
	_ = eventFilter
}