package main

import (
	"fmt"
	"log"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	client := iota_sdk.GraphQlClientNewLocalnet()
	address, err := iota_sdk.AddressFromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}

	faucet := iota_sdk.FaucetClientNewLocalnet()
	_, err = faucet.RequestAndWaitForFinalized(address, client)
	if err != nil {
		log.Fatalf("Failed to request faucet: %v", err)
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
		fmt.Println(obj.ObjectId().ToHex())
	}
}
