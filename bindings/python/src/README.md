# IOTA SDK Library - Python bindings

This library provides Python bindings to the [`IOTA SDK v3`](https://github.com/iotaledger/iota-rust-sdk).

Note that this library was automatically generated using [`uniffi-rs`](https://github.com/mozilla/uniffi-rs) and [`maturin`](https://github.com/PyO3/maturin).

## Installation

To add this library as a dependency to your 3.8+ Python project, run:

```sh
pip install iota-sdk
```

Note that for this command to work your shell should be running a virtual Python environment.

## Minimum example

You can check your installation by running the following example code:

```python
from iota_sdk import *

import asyncio

async def main():
    client = GraphQlClient.new_devnet()

    chain_id = await client.chain_id()
    print("Chain ID:", chain_id)

if __name__ == "__main__":
    asyncio.run(main())
```
