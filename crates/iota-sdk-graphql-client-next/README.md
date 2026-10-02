# iota-sdk-graphql-client-next

A client for the IOTA GraphQL RPC service.

## Requests

Every query method returns a request that is sent when awaited. Its methods set
the query's optional inputs:

```rust,ignore
use iota_sdk_graphql_client_next::GraphQLClient;

let client = GraphQLClient::testnet()?;

let object = client.object(object_id).version(version).await?;
let epoch = client.epoch().await?;
```

### Result forms

Where a query can return its result in more than one form, the request's
methods choose the form, and the form decides which fields the query fetches:

```rust,ignore
let object = client.object(id).await?; // Option<Object>, from its BCS
let contents = client.object(id).json().await?; // the JSON of its contents
let coin = client.object(id).decode::<Coin<IOTA>>().await?; // with `move-types`

let transaction = client.transaction(digest).await?;
let effects = client.transaction(digest).effects().await?;
let both = client.transaction(digest).with_effects().await?;
```

### Pagination

List queries take GraphQL's connection arguments, `first`/`after` to page
forward and `last`/`before` to page backward, and resolve to a `Page`. Without
a page size the server's default applies.

`pages()` and `items()` walk the list. A walk ends at the first error; every
page carries the cursors to resume from:

```rust,ignore
use futures::TryStreamExt;

let coins = client.coins(owner).first(50).items().try_collect::<Vec<_>>().await?;

let page = client.events().sender(sender).last(10).await?;
let older = client.events().sender(sender).last(10).before(page.start_cursor().cloned().unwrap()).await?;
```

## Executing transactions

`execute` resolves to the transaction's effects once a validator quorum has
executed it. Waiting until queries see the transaction is a separate step, so
its effects are never lost to a slow indexer:

```rust,ignore
let effects = client.execute(&transaction, &signatures).await?;
client.wait_for_transaction(transaction.digest()).await?;
```

The client implements the traits of `iota-sdk-client-api`, so it can back the
transaction builder.

## Errors and retries

`Error` tells apart failures to reach the server, errors the server reports
(with their `extensions.code`), responses that do not have the expected shape,
invalid inputs, and timeouts. `Error::is_retryable` says whether sending the
same request again may succeed; the client retries those failures itself,
following its `RetryPolicy`.

## Configuration

```rust,ignore
use std::time::Duration;

let client = GraphQLClient::builder("https://graphql.testnet.iota.cafe")
    .header("x-api-key", key)
    .timeout(Duration::from_secs(10))
    .retry(RetryPolicy::new(5))
    .build()?;
```

Requests go through a `Transport`. The default one is built on `reqwest`, with a
connect timeout of 5 seconds; pass your own `reqwest::Client` with
`reqwest_client`, e.g. to set a proxy or another connect timeout, or any other
transport with `transport`. The client sets its headers, timeout and retries on
top of either. Start your own `reqwest::Client` from
`ReqwestTransport::default_client_builder()` to keep the default transport's TLS
setup:

```rust,ignore
let http = ReqwestTransport::default_client_builder()
    .connect_timeout(Duration::from_secs(3))
    .build()?;
let client = GraphQLClient::builder(endpoint).reqwest_client(http).build()?;
```

## Server versions

The client reads the server's version from its responses. Queries that select
fields only newer servers have choose their selection from it, so the same call
works against servers on different versions: a dry run reports the suggested
gas price on servers since 1.33, and leaves it out on older ones.

## Custom queries

`Query` describes an operation and how to decode its response. Implement it
with your own `cynic` fragments, registered with `iota-sdk-graphql-client-build`,
and send it with `GraphQLClient::send` to use the client's transport, retries
and errors.

## TLS

The built-in transport verifies HTTPS with `rustls`. Every axis has a default,
so reaching the public networks needs no setup.

| Feature            | Default | Effect                                                                                                                                                                                                                                                                                                       |
| ------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tls-ring`         | on      | `ring` as the `rustls` crypto provider                                                                                                                                                                                                                                                                       |
| `tls-aws-lc`       | off     | `aws-lc-rs` instead; builds a C library, so it needs a C toolchain and `libclang` on targets without prebuilt bindings. `tls-ring` wins if both are on.                                                                                                                                                      |
| neither provider   | —       | HTTP-only: `reqwest` is built without TLS, the root features below are ignored, and building a client for an `https` endpoint fails rather than letting its requests fail later.                                                                                                                             |
| `tls-native-roots` | on      | trust the platform store. Alone it changes nothing, since that is already `reqwest`'s default; its effect is to merge rather than replace when `tls-webpki-roots` is also on.                                                                                                                                |
| `tls-webpki-roots` | on      | add the bundled Mozilla roots, merged into the platform store when `tls-native-roots` is also on. Merging is a union, not a fallback: a CA the platform has deliberately distrusted is still accepted if the bundled set carries it. Turn off `tls-native-roots` if the bundled set should be authoritative. |
| neither roots      | —       | the platform store alone. `reqwest` constructs its verifier eagerly, so on Linux an empty system store fails the build even for plain-HTTP use, which the bundled roots otherwise prevent.                                                                                                                   |

Android always uses the bundled roots alone: it cannot merge the two, and its
platform verifier aborts the process unless the application performs a JNI
handshake this crate cannot do on its behalf. On wasm32 the browser owns
certificate verification.

The `reqwest` feature, on by default, provides the built-in transport. Without
it, set a transport on the builder.
