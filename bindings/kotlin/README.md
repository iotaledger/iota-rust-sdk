# Kotlin

## Generate Binding

```bash
#!/bin/bash
LANGUAGE="kotlin"
# Start by building the library to generate the appropriate dylib files
cargo build -p iota-sdk-ffi --lib --release
# Determine the library extension based on the platform
case "$(uname -s)" in
  Darwin)   LIB_EXT=".dylib" ;;
  Linux)    LIB_EXT=".so" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) LIB_EXT=".dll" ;;
  *)        echo "Unsupported platform"; exit 1 ;;
esac
cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi${LIB_EXT}" --language $LANGUAGE --out-dir bindings/$LANGUAGE/lib --no-format -c bindings/kotlin/uniffi.toml
# Finally, copy the library file to the output directory.
cp target/release/libiota_sdk_ffi${LIB_EXT} bindings/$LANGUAGE/lib/
```

# Run an example

Install gradle:

```bash
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install gradle
```

`java -version` should be >= 21

```bash
cd bindings/kotlin

./gradlew build clean
LD_LIBRARY_PATH=./lib ./gradlew example -Pexample=chain_id
```

or

```sh
make kotlin-example chain_id
```
