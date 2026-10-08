# Examples

Each example does what the example of the same name in
[`crates/iota-sdk/examples`](../../iota-sdk/examples) does with
`iota-sdk-graphql-client`, so the two APIs can be compared side by side:

```sh
diff crates/iota-sdk/examples/get_object.rs crates/iota-sdk-graphql-client-next/examples/get_object.rs
```

| Example                                              | Change it shows                                                                                                       |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `chain_id`                                           | the network constructors return a `Result` instead of panicking                                                       |
| `get_object`                                         | `version` and `json` set on the request, instead of an `Option` argument and a separate `move_object_contents` method |
| `coin_balances`                                      | `balance` resolves to a `Balance` with the coin type and count; `balances` lists every coin type                      |
| `get_transaction`                                    | `effects` and `with_effects` on one request, instead of three methods                                                 |
| `owned_objects`, `objects_by_type`                   | filters set on the request, instead of `ObjectFilter` and `PaginationFilter` arguments                                |
| `pagination`                                         | `first` and `after` instead of a hand-built `PaginationFilter`, and the `items` and `pages` streams                   |
| `package_events`                                     | a typed event type filter, and events that carry their transaction digest                                             |
| `epoch`                                              | `id` set on the request, instead of an `Option` argument                                                              |
| `transactions_with_function`, `address_transactions` | typed filters instead of strings, and `affected_address` for both directions in one query                             |
| `move_objects`                                       | `objects().decode::<T>()`, for one page or as a stream, instead of `move_objects::<T>` and `move_objects_stream::<T>` |
| `dry_run_bytes`                                      | `skip_checks` set on the request, and the suggested gas price from servers since 1.33                                 |
| `sign_send_iota`                                     | the transaction builder backed by the new client, and `execute` followed by `wait_for_transaction`                    |
| `custom_query`                                       | a `Query` sent with `send`, getting the client's retries and error handling, instead of `run_query`                   |

These have no counterpart: `configuration` (headers, timeouts, retries and your
own `reqwest::Client`), `errors` (error kinds and retryability) and
`custom_transport` (a transport that logs every request).

Run one with `cargo run -p iota-sdk-graphql-client-next --example <name>`.
`move_objects` needs `--features move-types`, and `sign_send_iota` runs against
a local network with a funded sender. The others run against testnet.
