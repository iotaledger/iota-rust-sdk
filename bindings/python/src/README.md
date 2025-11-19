# IOTA SDK Library - Python bindings

This library provides Python bindings for the official [`IOTA SDK`](https://github.com/iotaledger/iota-rust-sdk).

Note that these bindings were automatically generated using [`uniffi-rs`](https://github.com/mozilla/uniffi-rs).

## Installation

To add this library as a dependency to your 3.9+ Python project, first make sure you have created a [`virtual environment`](https://docs.python.org/3/library/venv.html), then run the command:

```sh
pip install iota-sdk==3.0.0a1
```

You can check your installation by running the following minimum example:

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
