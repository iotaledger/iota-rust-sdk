package main

import (
	"fmt"

	sdk "bindings/iota_sdk_ffi"
)

func main() {
	client := sdk.GraphQlClientNewDevnet()
	address, err := sdk.AddressFromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")
	if err != nil {
		panic(err)
	}

	// Limit to 1 to demonstrate pagination
	limit := int32(1)
	var allObjects []*sdk.Object
	var nextCursor *string
	for {
		if nextCursor != nil {
			fmt.Printf("Fetching page with cursor: %s\n", *nextCursor)
		} else {
			fmt.Printf("Fetching page with cursor: nil\n")
		}
		page, err := client.Objects(&sdk.ObjectFilter{Owner: &address}, &sdk.PaginationFilter{Direction: sdk.DirectionForward, Cursor: nextCursor, Limit: &limit})
		if err.(*sdk.SdkFfiError) != nil {
			panic(err)
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
	fmt.Printf("Total objects fetched(%d):\n", len(allObjects))
	for _, obj := range allObjects {
		fmt.Println(obj.ObjectId().ToHex())
	}
}
