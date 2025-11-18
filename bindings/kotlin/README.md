# IOTA SDK - Kotlin Bindings

## Prerequisites

Make sure to have those dependencies installed on your system:

- GNU Make
- Gradle

It is recommended to install `Gradle` through:

```bash
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install gradle
```

Verify by running `make --version` and `gradle --version`.

## Generate Kotlin bindings

```bash
make kotlin
```

## Run Kotlin example

```sh
make kotlin-example chain_id
```
