# IOTA SDK - Python Bindings

## Prerequisites

Make sure to have those dependencies installed on your system:

- GNU Make
- Python3

Please follow the general install instructions for your platform.

Verify by running `make --version` and `python3 --version`.

## Generate Python bindings

```bash
make python
```

## Run Python example

```sh
make python-example chain_id
```

## Publishing to PyPi (Python Package Index)

### Dry Run Testing

To test the publishing process without actually publishing to PyPi:

1. Go to the Actions tab in GitHub
2. Select "Publish to PyPi" workflow
3. Click "Run workflow"
4. Check "Publish to TestPyPI only (Dry Run)"
5. Optionally specify a version
6. Run the workflow

This will build all artifacts and publish them to `https://test.pypi.org/`.

### Local Testing

You can also test creating and installing a python wheel (`.whl`) locally:

1. `pipx install maturin` (cargo install maturin fails to compile unless you install their latest main)
2. `cargo install --path crates/iota-sdk-ffi --bin uniffi-bindgen`
3. `cd bindings/python/src`
4. `maturin build --release` (you'll find the generated `.whl` in target/wheels)
5. Create a python test project with a virtual environment
6. `pip install target/wheels/iota_sdk-0.1.0-<PLATFORM_SPECIFIC>.whl`
7. Paste and run:

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
