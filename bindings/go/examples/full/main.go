package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-sdk-go"
)

func main() {
	client := iota_sdk.GraphQlClientNewDevnet()

	chainID, err := client.ChainId()
	if err.(*iota_sdk.SdkFfiError) != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Println("Chain ID:", chainID)
}