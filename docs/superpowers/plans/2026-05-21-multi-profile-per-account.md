# Multi-Profile-Per-Account Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate one AWS CLI profile per (account, role) pair in `oktaws init-sso`, including profiles for JIT-gated permission sets declared in the oktaws config file.

**Architecture:**

- Today, `init-sso` emits exactly one profile per AWS account, with the user selecting a single "default role" interactively. We flip this to emit a profile for *every* role visible on each account. One role per account remains "default" and gets the bare `account-name` profile (preserving the existing convention); all other roles get a suffixed `account-name/RoleName` profile using `/` as the separator.
- JIT-gated permission sets are invisible to the IAMIC API during inactive windows. To declare profiles speculatively, oktaws reads a new `[sso] extra_roles = [...]` field from `~/.oktaws/<org>.toml`. These roles are presumed JIT and are *excluded* from default-role candidacy so the bare `account-name` profile always points at an always-on role.
- For each account, the final role set is `api_roles ∪ extra_roles`. The default-role choice considers only `api_roles`. If `api_roles` is empty for an account (only JIT roles visible), no bare profile is emitted — only suffixed ones — and a warning is printed.

**Tech Stack:** Rust, `serde` + `toml` (already deps) for oktaws config, `configparser` (already a dep) for the `~/.aws/config` INI file, `dialoguer` for prompts, `tempfile`/`mockall` for tests.

**Files touched:**

- Create: [src/config/sso.rs](src/config/sso.rs) — new `SsoConfig` struct and `load_sso_config` loader (separate from federated `Organization` loader so init-sso-only users don't need a `[profiles]` table).
- Modify: [src/config/mod.rs](src/config/mod.rs) — `pub mod sso;`.
- Modify: [src/main.rs](src/main.rs) — add `sanitize_role_suffix`, `compute_account_default_role`, `expand_account_profiles`; rewire `init_sso`; remove dead `select_role_for_profile`.
- Modify: [README.md](README.md) — document multi-profile output and the `[sso]` section.

______________________________________________________________________

### Task 1: Add `SsoConfig` struct + loader for `~/.oktaws/<org>.toml`

**Files:**

- Create: [src/config/sso.rs](src/config/sso.rs)
- Modify: [src/config/mod.rs](src/config/mod.rs) — register the new module.

The existing `Config` in [src/config/organization.rs:27](src/config/organization.rs:27) requires a `profiles` table and runs federated-flow validation in `Organization::try_from` — overkill (and breaking for init-sso-only users) just to read `extra_roles`. Use a dedicated minimal deserializer that:

- Ignores all federated fields via serde's default permissive behavior.

- Treats a missing file or missing `[sso]` section as `Default::default()`.

- [ ] **Step 1: Register the new module**

In [src/config/mod.rs](src/config/mod.rs), change the first two lines:

```rust
pub mod organization;
pub mod profile;
pub mod sso;
```

- [ ] **Step 2: Write the failing tests**

Create `src/config/sso.rs` with this initial scaffold (tests first, no impl yet — will fail to compile, which is the "red" state):

```rust
use std::path::Path;

use eyre::Result;
use serde::{Deserialize, Serialize};

/// SSO-specific oktaws configuration, loaded from the `[sso]` section
/// of `~/.oktaws/<org>.toml`.
///
/// Defaults to all-empty values when the file or section is absent.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsoConfig {
    /// Permission set names that should produce profiles even when the IAMIC
    /// API does not currently list them for an account (typically JIT-gated roles).
    #[serde(default)]
    pub extra_roles: Vec<String>,
}

/// Load just the `[sso]` table from an oktaws org config file.
///
/// Returns `SsoConfig::default()` if the file does not exist or the `[sso]`
/// table is absent. Returns `Err` only on parse failure.
///
/// # Errors
///
/// Will return `Err` if the file exists but cannot be parsed as TOML.
pub fn load_sso_config(path: &Path) -> Result<SsoConfig> {
    if !path.exists() {
        return Ok(SsoConfig::default());
    }
    #[derive(Deserialize)]
    struct OktawsFile {
        #[serde(default)]
        sso: Option<SsoConfig>,
    }
    let raw = std::fs::read_to_string(path)?;
    let parsed: OktawsFile = toml::from_str(&raw)?;
    Ok(parsed.sso.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_missing_file_returns_default() -> Result<()> {
        let path = std::path::PathBuf::from("/this/path/does/not/exist.toml");
        assert_eq!(load_sso_config(&path)?, SsoConfig::default());
        Ok(())
    }

    #[test]
    fn test_load_file_without_sso_section_returns_default() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(
            file,
            r#"
username = "user"
[profiles]
foo = "foo-app"
"#
        )?;
        assert_eq!(load_sso_config(file.path())?, SsoConfig::default());
        Ok(())
    }

    #[test]
    fn test_load_file_with_sso_extra_roles() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(
            file,
            r#"
[sso]
extra_roles = ["AdminJIT", "BreakGlassJIT"]
"#
        )?;
        assert_eq!(
            load_sso_config(file.path())?,
            SsoConfig {
                extra_roles: vec!["AdminJIT".to_string(), "BreakGlassJIT".to_string()],
            }
        );
        Ok(())
    }

    #[test]
    fn test_load_file_with_sso_section_no_extra_roles() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        write!(
            file,
            r#"
[sso]
"#
        )?;
        assert_eq!(load_sso_config(file.path())?, SsoConfig::default());
        Ok(())
    }

    #[test]
    fn test_load_file_with_federated_and_sso_sections() -> Result<()> {
        // The federated config (username, profiles) must coexist with [sso]
        // without breaking the loader — we only care about [sso].
        let mut file = NamedTempFile::new()?;
        write!(
            file,
            r#"
username = "user"
role = "MyRole"

[profiles]
foo = "foo-app"

[sso]
extra_roles = ["AdminJIT"]
"#
        )?;
        assert_eq!(
            load_sso_config(file.path())?,
            SsoConfig {
                extra_roles: vec!["AdminJIT".to_string()],
            }
        );
        Ok(())
    }

    #[test]
    fn test_load_malformed_toml_errors() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "this is not valid toml [[[").unwrap();
        assert!(load_sso_config(file.path()).is_err());
    }
}
```

- [ ] **Step 3: Verify tests fail before impl is wired**

Wait — Step 2 already shipped a full implementation. To honor the TDD discipline, first delete the body of `load_sso_config` (replace with `todo!()`), confirm the test failures, then restore. Run:

```bash
# Temporarily replace impl body with todo!() to observe failure:
# (do this by editing src/config/sso.rs)
cargo test --lib config::sso::tests
```

Expected: all 6 tests fail/panic with `not yet implemented`.

- [ ] **Step 4: Restore the implementation and verify tests pass**

Restore the `load_sso_config` body from Step 2.

Run: `cargo test --lib config::sso::tests`
Expected: PASS (6 tests).

- [ ] **Step 5: Lint**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/config/mod.rs src/config/sso.rs
git commit -m "feat(config): add [sso] table loader for extra_roles"
```

______________________________________________________________________

### Task 2: Sanitize role-name suffixes for AWS profile names

**Files:**

- Modify: [src/main.rs](src/main.rs) — add `sanitize_role_suffix` helper + tests.

Unlike `sanitize_session_name` (which lowercases for filesystem-safe session names), this one preserves case because roles like `AdminAccess` and `adminaccess` should remain distinguishable in profile names.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `src/main.rs` (inside `mod tests`, before its closing `}`):

```rust
    #[test]
    fn test_sanitize_role_suffix_simple() {
        assert_eq!(sanitize_role_suffix("AdminAccess"), "AdminAccess");
    }

    #[test]
    fn test_sanitize_role_suffix_with_dashes_and_underscores() {
        assert_eq!(sanitize_role_suffix("Read-Only_Power"), "Read-Only_Power");
    }

    #[test]
    fn test_sanitize_role_suffix_spaces_become_dashes() {
        assert_eq!(sanitize_role_suffix("Power User"), "Power-User");
    }

    #[test]
    fn test_sanitize_role_suffix_strips_special_chars() {
        // Includes `/` — the suffix must never contain another `/`, since
        // `/` is the separator between account and role.
        assert_eq!(sanitize_role_suffix("Admin/JIT!"), "AdminJIT");
    }

    #[test]
    fn test_sanitize_role_suffix_preserves_case() {
        assert_eq!(sanitize_role_suffix("AdminAccess"), "AdminAccess");
        assert_ne!(sanitize_role_suffix("AdminAccess"), "adminaccess");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin oktaws tests::test_sanitize_role_suffix`
Expected: FAIL with "no function named `sanitize_role_suffix`".

- [ ] **Step 3: Implement `sanitize_role_suffix`**

Add this function to `src/main.rs`, immediately after `sanitize_session_name` (around line 346):

```rust
/// Sanitize a role name for use as a profile-name suffix.
///
/// Unlike `sanitize_session_name`, this preserves case (so `AdminAccess` and
/// `adminaccess` remain distinguishable). It keeps alphanumerics, underscores,
/// and hyphens; turns spaces into hyphens; and strips other characters — including
/// `/`, which is reserved as the account/role separator.
fn sanitize_role_suffix(name: &str) -> String {
    let mut result = String::new();
    let mut last_was_hyphen = false;

    for c in name.chars() {
        match c {
            ' ' | '-' => {
                if !last_was_hyphen && !result.is_empty() {
                    result.push('-');
                    last_was_hyphen = true;
                }
            }
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => {
                result.push(c);
                last_was_hyphen = false;
            }
            _ => {}
        }
    }

    if result.ends_with('-') {
        result.pop();
    }

    result
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --bin oktaws tests::test_sanitize_role_suffix`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(init-sso): add sanitize_role_suffix for profile name suffixes"
```

______________________________________________________________________

### Task 3: Compute the bare-profile default role per account

**Files:**

- Modify: [src/main.rs](src/main.rs) — add `compute_account_default_role` helper + tests.

This replaces the role-selection logic from `select_role_for_profile`, but constrained to API-discovered (always-on) roles only. The bare `account-name` profile must never point at a JIT-gated role.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `src/main.rs`:

```rust
    #[test]
    fn test_compute_account_default_role_single_api_role() {
        let result = compute_account_default_role(
            "prod-account",
            &["AdminAccess".to_string()],
            None,
            None,
        )
        .unwrap();
        assert_eq!(result, Some("AdminAccess".to_string()));
    }

    #[test]
    fn test_compute_account_default_role_existing_still_valid() {
        let result = compute_account_default_role(
            "prod-account",
            &["AdminAccess".to_string(), "ReadOnly".to_string()],
            Some("ReadOnly".to_string()),
            Some(&"AdminAccess".to_string()),
        )
        .unwrap();
        assert_eq!(result, Some("ReadOnly".to_string()));
    }

    #[test]
    fn test_compute_account_default_role_session_default_valid() {
        let result = compute_account_default_role(
            "prod-account",
            &["AdminAccess".to_string(), "ReadOnly".to_string()],
            None,
            Some(&"AdminAccess".to_string()),
        )
        .unwrap();
        assert_eq!(result, Some("AdminAccess".to_string()));
    }

    #[test]
    fn test_compute_account_default_role_no_api_roles_returns_none() {
        let result = compute_account_default_role(
            "prod-account",
            &[],
            None,
            Some(&"AdminAccess".to_string()),
        )
        .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_compute_account_default_role_session_default_not_in_api_roles() {
        let result = compute_account_default_role(
            "prod-account",
            &["ReadOnly".to_string()],
            None,
            Some(&"AdminJIT".to_string()),
        )
        .unwrap();
        assert_eq!(result, Some("ReadOnly".to_string()));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin oktaws tests::test_compute_account_default_role`
Expected: FAIL — function doesn't exist.

- [ ] **Step 3: Implement `compute_account_default_role`**

Add to `src/main.rs`, just before `select_role_for_profile` (around line 533):

```rust
/// Choose which role should back the bare `account-name` profile.
///
/// Candidates are restricted to `api_roles` — never `extra_roles` — so the bare
/// profile is always always-on (the whole point of the multi-profile model).
///
/// Returns `None` if `api_roles` is empty (account only has JIT roles available);
/// the caller should skip emitting a bare profile in that case.
///
/// Priority:
/// 1. Single API role available → use it (no prompt).
/// 2. Existing role from `~/.aws/config` that is still in `api_roles` → reuse it.
/// 3. Session default role that is in `api_roles` → use it.
/// 4. Otherwise → prompt interactively over `api_roles`.
fn compute_account_default_role(
    account_name: &str,
    api_roles: &[String],
    existing_role: Option<String>,
    session_default_role: Option<&String>,
) -> Result<Option<String>> {
    if api_roles.is_empty() {
        return Ok(None);
    }

    if api_roles.len() == 1 {
        return Ok(Some(api_roles[0].clone()));
    }

    if let Some(existing) = existing_role {
        if api_roles.contains(&existing) {
            return Ok(Some(existing));
        }
        println!(
            "  Note: Previously selected role '{existing}' is no longer always-on for {account_name}"
        );
        let selection = dialoguer::Select::new()
            .with_prompt(format!("Choose default (always-on) role for {account_name}"))
            .items(api_roles)
            .interact()?;
        return Ok(Some(api_roles[selection].clone()));
    }

    if let Some(default) = session_default_role {
        if api_roles.contains(default) {
            return Ok(Some(default.clone()));
        }
    }

    let selection = dialoguer::Select::new()
        .with_prompt(format!("Choose default (always-on) role for {account_name}"))
        .items(api_roles)
        .interact()?;
    Ok(Some(api_roles[selection].clone()))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --bin oktaws tests::test_compute_account_default_role`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(init-sso): compute bare-profile default role from API roles only"
```

______________________________________________________________________

### Task 4: Expand an account into (profile, role) pairs

**Files:**

- Modify: [src/main.rs](src/main.rs) — add `expand_account_profiles` + tests.

This function produces the full list of profiles to write for one account, using `/` as the account/role separator.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `src/main.rs`:

```rust
    #[test]
    fn test_expand_account_profiles_single_api_role_no_extras() {
        let result = expand_account_profiles(
            "prod",
            "111111111111",
            &["AdminAccess".to_string()],
            &[],
            Some(&"AdminAccess".to_string()),
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].profile_name, "prod");
        assert_eq!(result[0].role, "AdminAccess");
        assert_eq!(result[0].available_roles, vec!["AdminAccess".to_string()]);
    }

    #[test]
    fn test_expand_account_profiles_multiple_api_roles() {
        let result = expand_account_profiles(
            "prod",
            "111111111111",
            &["AdminAccess".to_string(), "ReadOnly".to_string()],
            &[],
            Some(&"AdminAccess".to_string()),
        );
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].profile_name, "prod");
        assert_eq!(result[0].role, "AdminAccess");
        assert_eq!(result[1].profile_name, "prod/ReadOnly");
        assert_eq!(result[1].role, "ReadOnly");
        assert_eq!(result[1].available_roles, vec!["ReadOnly".to_string()]);
    }

    #[test]
    fn test_expand_account_profiles_with_extra_roles() {
        let result = expand_account_profiles(
            "prod",
            "111111111111",
            &["AdminAccess".to_string()],
            &["AdminJIT".to_string(), "ReadOnlyJIT".to_string()],
            Some(&"AdminAccess".to_string()),
        );
        assert_eq!(result.len(), 3);
        let names: Vec<&str> = result.iter().map(|p| p.profile_name.as_str()).collect();
        assert_eq!(names, vec!["prod", "prod/AdminJIT", "prod/ReadOnlyJIT"]);
    }

    #[test]
    fn test_expand_account_profiles_no_api_roles_only_extras() {
        let result = expand_account_profiles(
            "prod",
            "111111111111",
            &[],
            &["AdminJIT".to_string()],
            None,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].profile_name, "prod/AdminJIT");
        assert_eq!(result[0].role, "AdminJIT");
    }

    #[test]
    fn test_expand_account_profiles_dedupes_overlap_between_api_and_extras() {
        let result = expand_account_profiles(
            "prod",
            "111111111111",
            &["AdminAccess".to_string(), "ReadOnly".to_string()],
            &["ReadOnly".to_string(), "AdminJIT".to_string()],
            Some(&"AdminAccess".to_string()),
        );
        assert_eq!(result.len(), 3);
        let names: Vec<&str> = result.iter().map(|p| p.profile_name.as_str()).collect();
        assert_eq!(names, vec!["prod", "prod/ReadOnly", "prod/AdminJIT"]);
    }

    #[test]
    fn test_expand_account_profiles_bare_profile_lists_api_roles_for_comments() {
        // The bare profile's available_roles drives the "# sso_role_name = X" alternative comments.
        // Only API roles should appear — comment-swapping to a JIT role would silently fail.
        let result = expand_account_profiles(
            "prod",
            "111111111111",
            &["AdminAccess".to_string(), "ReadOnly".to_string()],
            &["AdminJIT".to_string()],
            Some(&"AdminAccess".to_string()),
        );
        let bare = result.iter().find(|p| p.profile_name == "prod").unwrap();
        assert_eq!(
            bare.available_roles,
            vec!["AdminAccess".to_string(), "ReadOnly".to_string()]
        );
    }

    #[test]
    fn test_expand_account_profiles_sanitizes_role_suffix() {
        let result = expand_account_profiles(
            "prod",
            "111111111111",
            &["AdminAccess".to_string()],
            &["Power User".to_string()],
            Some(&"AdminAccess".to_string()),
        );
        let suffixed = &result[1];
        assert_eq!(suffixed.profile_name, "prod/Power-User");
        assert_eq!(suffixed.role, "Power User"); // role string verbatim; only profile name is sanitized
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --bin oktaws tests::test_expand_account_profiles`
Expected: FAIL — `expand_account_profiles` and `ExpandedProfile` don't exist.

- [ ] **Step 3: Implement the type and function**

Add to `src/main.rs`, immediately after `compute_account_default_role`:

```rust
/// One profile to write for an account, produced by `expand_account_profiles`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpandedProfile {
    profile_name: String,
    account_id: String,
    role: String,
    /// Roles to render as `# sso_role_name = X` comment alternatives in the AWS config.
    /// For the bare profile this is the full API-role set; for suffixed profiles it is
    /// just the single role.
    available_roles: Vec<String>,
}

/// Expand one account into the full set of profiles to write.
///
/// Produces:
/// - One bare `{base_profile_name}` profile pointing at `default_role` (if `Some`).
/// - One suffixed `{base_profile_name}/{sanitized_role}` profile for every other role in
///   `api_roles ∪ extra_roles`, deduped, preserving input order (api_roles first).
///
/// `base_profile_name` is the account's profile-name *after* collision-prefix resolution
/// has been applied by the caller — both bare and suffixed profiles share that base.
fn expand_account_profiles(
    base_profile_name: &str,
    account_id: &str,
    api_roles: &[String],
    extra_roles: &[String],
    default_role: Option<&String>,
) -> Vec<ExpandedProfile> {
    let mut all_roles: Vec<String> = Vec::with_capacity(api_roles.len() + extra_roles.len());
    for r in api_roles.iter().chain(extra_roles.iter()) {
        if !all_roles.contains(r) {
            all_roles.push(r.clone());
        }
    }

    let mut out = Vec::new();

    if let Some(default) = default_role {
        out.push(ExpandedProfile {
            profile_name: base_profile_name.to_string(),
            account_id: account_id.to_string(),
            role: default.clone(),
            available_roles: api_roles.to_vec(),
        });
    }

    for role in &all_roles {
        if default_role.is_some_and(|d| d == role) {
            continue;
        }
        out.push(ExpandedProfile {
            profile_name: format!("{base_profile_name}/{}", sanitize_role_suffix(role)),
            account_id: account_id.to_string(),
            role: role.clone(),
            available_roles: vec![role.clone()],
        });
    }

    out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --bin oktaws tests::test_expand_account_profiles`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(init-sso): expand each account into multiple (profile, role) pairs"
```

______________________________________________________________________

### Task 5: Wire `init_sso` to load oktaws SSO config + use new helpers

**Files:**

- Modify: [src/main.rs](src/main.rs) — load `extra_roles` from `~/.oktaws/<org>.toml`; rewire profile-writing loop; reword default-role prompt.

- [ ] **Step 1: Import the new module**

In `src/main.rs`, add to the existing oktaws imports at the top (alongside `oktaws::config::oktaws_home`, around line 7):

```rust
use oktaws::config::sso::load_sso_config;
```

- [ ] **Step 2: Reword `prompt_for_default_role` to make "always-on" explicit**

In `src/main.rs`, replace the `dialoguer::Select::new()` block inside `prompt_for_default_role` (lines ~481-488):

```rust
            let selection = dialoguer::Select::new()
                .with_prompt(format!(
                    "Choose default (always-on) role for {display_name} ({needs_selection_count} account{} need a default)",
                    if needs_selection_count == 1 { "" } else { "s" }
                ))
                .items(&options)
                .default(0)
                .interact()?;
```

- [ ] **Step 3: Replace the inner role-selection + write loop in `init_sso`**

In `src/main.rs`, locate the block in `init_sso` that begins with `// Write sessions and profiles with appropriate names` (around line 654). Replace the entire `for (session_name, display_name, start_url, region, sso_profiles) in sessions { ... }` loop body (from `// Create SSO session` through the matching closing `}` at ~line 711) with:

```rust
        // Create SSO session
        aws_config.upsert_sso_session(&session_name, &start_url, &region)?;

        // Load extra (JIT-gated) roles declared in the oktaws config for this org.
        // These are presumed always-JIT and excluded from default-role candidacy.
        let oktaws_config_path =
            oktaws_home()?.join(format!("{}.toml", options.organization));
        let sso_config = load_sso_config(&oktaws_config_path)?;
        let extra_roles = sso_config.extra_roles;

        // Determine which accounts need a default-role prompt.
        // An account needs one if it has multiple API roles AND no valid existing default.
        let mut needs_selection_profiles = Vec::new();
        for (account_name, (_, api_roles)) in &sso_profiles {
            let base_profile_name =
                determine_final_profile_name(account_name, &session_name, &needs_prefix);
            let existing_role = aws_config.get_profile_role(&base_profile_name);

            if profile_needs_role_selection(api_roles, existing_role) {
                needs_selection_profiles.push(account_name.clone());
            }
        }

        let session_default_role = if needs_selection_profiles.is_empty() {
            None
        } else {
            prompt_for_default_role(&display_name, needs_selection_profiles.len(), &sso_profiles)?
        };

        // Expand and write profiles.
        println!("\nSSO profiles for {display_name} (session: {session_name}):");
        for (account_name, (account_id, api_roles)) in &sso_profiles {
            let base_profile_name =
                determine_final_profile_name(account_name, &session_name, &needs_prefix);
            let existing_role = aws_config.get_profile_role(&base_profile_name);

            let default_role = compute_account_default_role(
                account_name,
                api_roles,
                existing_role,
                session_default_role.as_ref(),
            )?;

            if default_role.is_none() && !extra_roles.is_empty() {
                println!(
                    "  ! {account_name}: no always-on roles visible; emitting only JIT-suffixed profiles"
                );
            }

            let expanded = expand_account_profiles(
                &base_profile_name,
                account_id,
                api_roles,
                &extra_roles,
                default_role.as_ref(),
            );

            let sanitized = sanitize_session_name(account_name);
            let prefixed_note = if needs_prefix.contains(&sanitized) {
                " (prefixed due to collision with other session)"
            } else {
                ""
            };

            for profile in expanded {
                aws_config.upsert_sso_profile(
                    &profile.profile_name,
                    &session_name,
                    &profile.account_id,
                    &profile.role,
                    profile.available_roles,
                )?;
                println!("  - {}{prefixed_note}", profile.profile_name);
                total_profiles += 1;
            }
        }
```

Note that `extra_roles` is loaded *inside* the session loop. That's redundant (re-reads the file per session) but harmless — and importantly, it scopes the file-read errors to where session-specific output happens. If preferred, hoist it above the `for ... sessions` loop; either is acceptable.

- [ ] **Step 4: Build to verify the rewrite compiles**

Run: `cargo build`
Expected: clean build.

- [ ] **Step 5: Run the full test suite**

Run: `cargo test`
Expected: all tests pass. `select_role_for_profile` is no longer called from `init_sso` but still defined — that's addressed in Task 6.

- [ ] **Step 6: Lint**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: may flag `select_role_for_profile` as dead code. If so, allow it temporarily by adding `#[allow(dead_code)]` above its definition — Task 6 deletes it.

- [ ] **Step 7: Commit**

```bash
git add src/main.rs
git commit -m "feat(init-sso): emit one profile per (account, role) pair with JIT-aware default"
```

______________________________________________________________________

### Task 6: Remove dead code (`select_role_for_profile`)

**Files:**

- Modify: [src/main.rs](src/main.rs) — remove the now-unused function and its tests (if any).

- [ ] **Step 1: Verify it's actually dead**

Run: `grep -n "select_role_for_profile" src/main.rs`
Expected: only the function definition (and any `#[allow(dead_code)]` annotation added in Task 5 Step 6) — no callers.

- [ ] **Step 2: Delete the function and its doc comment**

In `src/main.rs`, remove the function `select_role_for_profile` (search for `fn select_role_for_profile(` to find it). Delete the function definition, its preceding doc comment block, and any `#[allow(dead_code)]` annotation added in Task 5.

Also search for `#[test]` functions whose body calls `select_role_for_profile` — `grep -n "select_role_for_profile" src/main.rs` after the delete should return zero matches. If any test calls remain, delete those tests too.

- [ ] **Step 3: Verify build + tests + lint**

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "refactor(init-sso): remove unused select_role_for_profile"
```

______________________________________________________________________

### Task 7: Document the new behavior

**Files:**

- Modify: [README.md](README.md) — add sections for multi-profile output and the oktaws `[sso]` config table.

- [ ] **Step 1: Add documentation**

In `README.md`, locate the line `**Note:** \`~/.aws/config\` is modified by \`init-sso\` but only read by other commands.\` (in the "For AWS Identity Center/SSO" setup section). Immediately after that line, append:

````markdown
#### Multiple Profiles Per Account

`init-sso` generates one AWS profile per (account, role) pair visible on each account. The role chosen as that account's "default" is written to the bare profile name (matching the account name); every other role gets a suffixed profile of the form `account-name/RoleName`.

Example: an account `prod` with roles `AdminAccess` and `ReadOnly`, where you select `AdminAccess` as the default, produces:

```
[profile prod]
sso_role_name = AdminAccess
# sso_role_name = ReadOnly
...

[profile prod/ReadOnly]
sso_role_name = ReadOnly
...
```

#### JIT-Gated Roles (`extra_roles`)

When IAM Identity Center permission sets are gated behind just-in-time access, they are invisible to `init-sso` during inactive windows — so no profile gets generated for them. To declare profiles speculatively, add an `[sso]` section to `~/.oktaws/<okta-org>.toml`:

```toml
[sso]
extra_roles = ["AdminJIT", "BreakGlassJIT"]
```

On the next `init-sso` run, oktaws will emit an `account-name/AdminJIT` profile (and similar for other entries) for every account in every SSO session belonging to this Okta org. `aws sso login --profile account-name/AdminJIT` will only succeed during an active JIT window — outside of one, it fails cleanly.

`extra_roles` are never chosen as the bare profile's default role: the bare `account-name` profile is always backed by an always-on (API-discovered) role, so it never silently fails. Accounts with only JIT roles visible get suffixed profiles only, and `init-sso` prints a warning for those.

This section coexists with `[profiles]` (used by the federated SAML flow); init-sso ignores `[profiles]` and federated commands ignore `[sso]`.
````

- [ ] **Step 2: Spot-check the rendering**

Run: `head -120 README.md`
Expected: new sections appear under the AWS Identity Center/SSO setup section.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document multi-profile-per-account and [sso].extra_roles"
```

______________________________________________________________________

## Self-Review

**Spec coverage:** Every design point from the conversation is covered —

- Multi-profile-per-account (Tasks 2, 4, 5)
- Bare `account-name` for default role, preserving convention (Tasks 3, 4)
- `/` separator between account and role (Tasks 2, 4)
- `extra_roles` in oktaws TOML, not `~/.aws/config` (Task 1, used in Task 5)
- Always-on default selection (Tasks 3, 5)
- Re-run idempotency via existing-role reuse (Tasks 3, 5)
- Documentation (Task 7)
- Dead-code cleanup (Task 6)

**Placeholder scan:** No "TBD" / "implement later" placeholders.

**Type/name consistency:** `SsoConfig` (Task 1) has field `extra_roles: Vec<String>` — consumed by Task 5 as `sso_config.extra_roles`. `ExpandedProfile` (Task 4) has fields `profile_name`, `account_id`, `role`, `available_roles` — consumed by Task 5's `aws_config.upsert_sso_profile(..., profile.available_roles)` matching the existing signature. `compute_account_default_role` returns `Result<Option<String>>` — consumed by Task 5 as `default_role.as_ref()` passed into `expand_account_profiles`.

**Notable behavioral choices baked into the plan:**

1. `extra_roles` is org-wide (every SSO session in the org gets every extra role applied to every account). Per-session and per-account scoping deferred — most orgs have a single SSO app and a small JIT role count.
1. The bare profile's `available_roles` (used for `# sso_role_name = X` comment alternatives in `~/.aws/config`) lists only API roles. Comment-swapping is therefore always to another always-on role.
1. Role-suffix sanitization preserves case (`AdminAccess` ≠ `adminaccess`) and strips `/` (the reserved separator). Account-name portion is still lowercased via the existing `sanitize_session_name`.
1. Per-session re-load of `extra_roles` inside the loop is mildly redundant; acceptable for clarity.

______________________________________________________________________

## Execution

Per the user's CLAUDE.md, this plan will be executed via **superpowers:subagent-driven-development** — one subagent per task with review between tasks.
