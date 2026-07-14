# Rust 2024 Formatting Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate oktaws to Rust edition 2024 and guarantee that `cargo fmt` and `nix fmt` use the same manifest-declared edition.

**Architecture:** `Cargo.toml` remains the authoritative crate metadata. The treefmt-nix rustfmt integration reads the package edition from that manifest instead of relying on treefmt-nix's default, so both formatter entry points pass edition 2024 to the same rustfmt behavior.

**Tech Stack:** Rust 2024, Cargo, rustfmt 1.9.0, Nix flakes, treefmt-nix

## Global Constraints

- Set the crate edition to exactly `2024`.
- Read treefmt's rustfmt edition from `Cargo.toml`; do not duplicate the edition string in `treefmt.nix`.
- Limit source changes to compiler-required edition migration edits and rustfmt output.
- Add no dependency and perform no unrelated refactor.
- Use formatter convergence plus the existing check, test, clippy, and Nix flake checks as regression coverage; do not add a unit test for configuration-only behavior.

______________________________________________________________________

## File Structure

- Modify `Cargo.toml`: declare Rust edition 2024 as the single source of truth.
- Modify `treefmt.nix`: pass the manifest edition to treefmt-nix's rustfmt module.
- Modify `src/**/*.rs` only if `cargo fix --edition` or edition-2024 rustfmt requires changes.
- Create no production or test files.

### Task 1: Migrate to Rust 2024 and converge the formatters

**Files:**

- Modify: `Cargo.toml:63-73`
- Modify: `treefmt.nix:15-21`
- Modify if required: `src/**/*.rs`
- Test: existing Rust test targets and formatter checks

**Interfaces:**

- Consumes: `Cargo.toml` package metadata and treefmt-nix's `programs.rustfmt.edition` option.

- Produces: a Rust 2024 crate for which Cargo and treefmt invoke rustfmt with the same edition.

- [ ] **Step 1: Re-run the failing formatter regression check**

Run:

```bash
nix develop -c cargo fmt --all -- --check
```

Expected: FAIL with edition-sensitive diffs such as `eyre::{Result, eyre}` becoming `eyre::{eyre, Result}`. This proves the committed edition-2024 treefmt output still disagrees with Cargo while the manifest says edition 2021.

- [ ] **Step 2: Apply Cargo's edition compatibility migration**

Run while `Cargo.toml` still declares edition 2021:

```bash
nix develop -c cargo fix --edition --all-targets --all-features
```

Expected: exit 0. Cargo applies any compiler-suggested edition-2024 compatibility rewrites without changing the manifest edition.

Review any changed Rust files immediately:

```bash
git diff -- src
```

Expected: only compiler-suggested compatibility changes, or no diff when the existing code is already edition-2024 compatible.

- [ ] **Step 3: Change the manifest edition and connect treefmt to it**

Apply this patch:

```diff
*** Begin Patch
*** Update File: Cargo.toml
@@
-edition = "2021"
+edition = "2024"
*** Update File: treefmt.nix
@@
-      programs.rustfmt.enable = true; # rust
+      programs.rustfmt = {
+        enable = true; # rust
+        edition =
+          (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.edition;
+      };
*** End Patch
```

Expected: the crate and treefmt both obtain edition `2024` from `Cargo.toml`.

- [ ] **Step 4: Apply canonical formatting once**

Run:

```bash
nix develop -c cargo fmt --all
nix fmt
```

Expected: both commands succeed. The first applies Rust 2024 formatting; the second formats every configured repository file and makes no opposing Rust edits.

- [ ] **Step 5: Verify formatter convergence**

Run:

```bash
nix develop -c cargo fmt --all -- --check
nix fmt -- --fail-on-change
nix develop -c cargo fmt --all -- --check
```

Expected: all three commands exit 0; treefmt reports zero changed files, and both Cargo checks are clean.

- [ ] **Step 6: Run the Rust and Nix verification suite**

Run:

```bash
nix develop -c cargo check --all-targets --all-features
nix develop -c cargo test --all-targets --all-features
nix develop -c cargo clippy --all-targets --all-features -- -D warnings
nix flake check --print-build-logs --no-update-lock-file
```

Expected: every command exits 0. Tests pass, clippy emits no warnings, and the flake's clippy, nextest, and treefmt checks succeed.

- [ ] **Step 7: Review the completed migration**

Run:

```bash
git diff --check
git diff --stat
git diff -- Cargo.toml treefmt.nix src
git status --short
```

Expected: no whitespace errors; the diff contains only the manifest edition, the treefmt edition linkage, compiler-required compatibility edits, and Rust 2024 formatting.

- [ ] **Step 8: Commit the implementation**

Stage only the reviewed migration files, including any Rust files actually changed:

```bash
git add Cargo.toml treefmt.nix src
git commit -m "build: migrate to Rust 2024 edition"
```

Expected: one focused implementation commit after the separate design and plan commits.
