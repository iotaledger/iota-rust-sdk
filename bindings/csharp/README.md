# IOTA Rust SDK C# Bindings (Milestone 1 scaffold)

This directory bootstraps the C# binding work tracked in [#495](https://github.com/iotaledger/iota-rust-sdk/issues/495).

## Scope in this milestone

- C# binding folder and project layout scaffold.
- Two translated examples from existing bindings:
  - `GenerateMnemonic.cs`
  - `AddressFromMnemonic.cs`
- Makefile/CI hook for scaffold and formatting checks.

> [!NOTE]
> The generated UniFFI C# surface is not landed yet in this milestone.
> Example files are intentionally written against the expected API shape and are marked as `Compile Remove` in the sample project so CI can validate formatting and structure without blocking on generator/runtime wiring.

## Layout

- `IotaSdk.Bindings.csproj` — placeholder project for future generated bindings.
- `IotaSdk.Examples.csproj` — example console app project.
- `examples/*.cs` — translated examples.

## Next steps (PR 2+)

1. Wire UniFFI C# generation into `make csharp`.
2. Commit generated C# bindings into a dedicated `lib/` folder (or generation script with deterministic output).
3. Switch examples from `Compile Remove` to actual compilation.
4. Add runtime example execution in CI (likely against localnet for networked examples).
