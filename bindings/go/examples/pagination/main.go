package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewTestnet()
	address, err := iota_sdk.AddressFromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	// Limit to 1 to demonstrate pagination
	limit := int32(1)
	var allObjects []*iota_sdk.Object
	var nextCursor *string
	for {
		if nextCursor != nil {
			fmt.Printf("Fetching page with cursor: %s\n", *nextCursor)
		} else {
			fmt.Printf("Fetching page with cursor: nil\n")
		}
		page, err := client.Objects(&iota_sdk.ObjectFilter{Owner: &address}, &iota_sdk.PaginationFilter{Direction: iota_sdk.DirectionForward, Cursor: nextCursor, Limit: &limit})
		if err != nil {
			log.Fatalf("Failed to get owned objects: %v", err)
		}
		for _, obj := range page.Data {
			allObjects = append(allObjects, obj)
		}
		if page.PageInfo.HasNextPage {
			nextCursor = page.PageInfo.EndCursor
		} else {
			break
		}
	}
	fmt.Printf("%d objects fetched:\n", len(allObjects))
	for _, obj := range allObjects {
		fmt.Println(obj.Id().ToHex())
	}
}
