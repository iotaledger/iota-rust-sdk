# iota-sdk-client-api

The operations every IOTA network client offers, as traits, together with the
types they exchange.

A client implements the traits for the capabilities its transport has:

- `LedgerClient`: reading objects, the protocol configuration and the reference
  gas price.
- `SimulationClient`: dry runs and gas budget estimates.
- `ExecutionClient`: executing a transaction and waiting until it is indexed or
  finalized.

Code written against these traits works with any client that implements them,
such as the transaction builder, which resolves and executes transactions
through them.

## Implementing a client

Pick an error type in `Client`, then implement the capability traits your
transport supports. `LedgerClient::objects_by_id` has a default implementation
that fetches one object per request; override it when the transport can fetch a
batch.

```rust,ignore
use iota_sdk_client_api::{Client, LedgerClient};

struct MyClient;

impl Client for MyClient {
    type Error = MyError;
}

impl LedgerClient for MyClient {
    // ...
}
```
