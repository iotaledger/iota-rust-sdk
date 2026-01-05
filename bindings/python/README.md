# IOTA SDK Library - Python Bindings

This document describes how to generate platform specific Python bindings for the IOTA SDK locally from the repository itself.

Instructions on how you can add the officially released Python bindings to your project via `pip` you can find [`here`](src/README.md).

## Prerequisites

Make sure to have those dependencies installed on your system:

- GNU Make
- Python3

Please follow the general install instructions for your platform.

Verify by running `make --version` and `python3 --version`.

## Generate Python bindings module `iota_sdk.py`

1. Build the bindings: `make python`
2. Test by running the following minimal example: `make python-example chain_id`
