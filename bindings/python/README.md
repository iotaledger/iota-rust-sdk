# IOTA SDK Library - Python Bindings

This document describes how to generate platform specific Python bindings for the IOTA SDK locally from the repository itself.

Instructions on how to install pre-built officially released Python bindings for your project you can find [`here`](src/README.md).

## Prerequisites

Make sure to have those dependencies installed on your system:

- GNU Make
- Python3

Please follow the general install instructions for your platform.

Verify by running `make --version` and `python3 --version`.

## Generate Python bindings module `iota_sdk_ffi.py`

1. Build the bindings: `make python`
2. Test by running the following minimal example: `make python-example chain_id`

## Generate Python bindings wheel `iota_sdk-*.whl`

1. Install `maturin`: `pipx install maturin`
2. Install `uniffi-bindgen`: `cargo install --path crates/iota-sdk-ffi --bin uniffi-bindgen`
3. Switch to the Python bindings package: `cd bindings/python/src`
4. Build the wheel: `maturin build --release` (you'll find the generated `.whl` in target/wheels)
5. Create or switch to your Python project with an activated virtual environment
6. Install the local wheel: `pip install target/wheels/iota_sdk-<VERSION>-<PLATFORM>.whl`
7. Test by running the following minimal example:

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
