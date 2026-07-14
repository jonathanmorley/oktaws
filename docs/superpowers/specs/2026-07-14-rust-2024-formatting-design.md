# Rust 2024 Formatting Alignment

## Context

`cargo fmt` and `nix fmt` currently produce opposing changes in 17 Rust source files. Both commands use rustfmt 1.9.0, but Cargo passes the crate edition declared in `Cargo.toml` (`2021`) while treefmt-nix defaults its rustfmt integration to edition `2024`. Rustfmt's edition-sensitive import ordering makes the two commands alternate between valid but different layouts.

## Decision

Migrate the crate to Rust edition 2024 and make `Cargo.toml` the single source of truth for the edition used by treefmt.

`Cargo.toml` will declare edition `2024`. `treefmt.nix` will parse `Cargo.toml` with Nix's built-in TOML parser and assign the package edition to `programs.rustfmt.edition`. This removes the hidden dependency on treefmt-nix's default and prevents the two formatter entry points from drifting during a future edition migration.

## Migration

Run Cargo's edition migration before changing the manifest so compiler-provided compatibility rewrites are applied while the crate is still on edition 2021. Then update the manifest to edition 2024, connect treefmt to the manifest edition, and apply the canonical Cargo formatting.

The migration stays limited to compiler-required edition changes, formatter output, and the two edition configuration points. It will not include unrelated refactoring.

## Failure Handling

If `cargo fix --edition` reports code that cannot be migrated automatically, handle only the reported incompatibilities and preserve existing behavior. If the manifest edition cannot be read by Nix, flake evaluation should fail immediately rather than silently falling back to a potentially different formatter edition.

## Verification

This configuration/toolchain migration does not add a unit test. Its regression proof is formatter convergence and the existing behavioral suite:

1. Run Cargo's formatter and confirm a second Cargo formatter check is clean.
2. Run `nix fmt` in fail-on-change mode and confirm it makes no Rust changes.
3. Re-run Cargo's formatter check to prove the two entry points converge.
4. Run the repository's Rust checks, tests, clippy, and Nix flake checks.
5. Review the final diff for changes outside the approved scope.

## Alternatives Considered

- Hardcode edition `2024` in both `Cargo.toml` and `treefmt.nix`. This is explicit but duplicates configuration and can drift again.
- Change only `Cargo.toml`. This is the smallest edit, but it relies on treefmt-nix continuing to default to edition 2024 and leaves the original hidden coupling in place.
