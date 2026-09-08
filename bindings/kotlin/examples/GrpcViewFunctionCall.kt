// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GrpcClient
import iota_sdk.MoveViewArg
import iota_sdk.ObjectId
import iota_sdk.ViewFunctionCallInput
import iota_sdk.ViewFunctionCallOutputs
import kotlinx.coroutines.runBlocking

// The `view_demo` package published on testnet.
const val GRPC_VIEW_DEMO_PACKAGE =
    "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4"

// A shared `view_demo::shop::Shop` created when the package was published.
const val GRPC_VIEW_DEMO_SHOP = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20"

fun describeOutputs(outputs: ViewFunctionCallOutputs): String {
    val returnValues = outputs.returnValues
    if (returnValues != null) {
        return "returned ${returnValues.map { it.json }}"
    }
    return "aborted (${outputs.executionError?.source})"
}

fun main() = runBlocking {
    try {
        val client = GrpcClient.newTestnet()

        // A single call. `discounted_price` is declared `#[view]` in the package.
        val outputs =
            client.viewFunctionCall(
                "$GRPC_VIEW_DEMO_PACKAGE::shop::discounted_price",
                null,
                listOf(MoveViewArg.u64(100uL), MoveViewArg.u64(25uL)),
            )
        println("discounted_price: ${describeOutputs(outputs)}")

        // Three calls in one request: the call from above, the same function with
        // a discount over 100% so that it aborts, and a function that is not
        // declared `#[view]`. Each call runs on its own, so the rejected one does
        // not affect the others.
        val shop = ObjectId.fromHex(GRPC_VIEW_DEMO_SHOP)
        val results =
            client.viewFunctionCalls(
                listOf(
                    ViewFunctionCallInput(
                        "$GRPC_VIEW_DEMO_PACKAGE::shop::discounted_price",
                        callArgs = listOf(MoveViewArg.u64(100uL), MoveViewArg.u64(25uL)),
                    ),
                    ViewFunctionCallInput(
                        "$GRPC_VIEW_DEMO_PACKAGE::shop::discounted_price",
                        callArgs = listOf(MoveViewArg.u64(100uL), MoveViewArg.u64(200uL)),
                    ),
                    ViewFunctionCallInput(
                        "$GRPC_VIEW_DEMO_PACKAGE::shop::record_sale",
                        callArgs = listOf(MoveViewArg.objectId(shop), MoveViewArg.u64(5uL)),
                    ),
                )
            )

        for ((name, result) in listOf("priced", "over-discounted", "record_sale").zip(results)) {
            val callOutputs = result.outputs
            if (callOutputs != null) {
                println("$name: ${describeOutputs(callOutputs)}")
            } else {
                println("$name: rejected by the node (${result.error})")
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
