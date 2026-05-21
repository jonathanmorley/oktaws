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

#[derive(Deserialize)]
struct OktawsFile {
    #[serde(default)]
    sso: Option<SsoConfig>,
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
            r"
[sso]
"
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
