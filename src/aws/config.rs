use configparser::ini::Ini;
use dirs;
use eyre::{Result, eyre};
use std::collections::HashMap;
use std::env::var as env_var;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::instrument;

/// A store for AWS config file (~/.aws/config)
/// Used for SSO sessions and SSO profiles
#[derive(Debug)]
pub struct ConfigStore {
    path: PathBuf,
    config: Ini,
    /// Maps profile names to their available roles (for commenting)
    profile_roles: HashMap<String, Vec<String>>,
}

impl ConfigStore {
    /// Load the AWS config file
    ///
    /// # Errors
    ///
    /// Will return `Err` if the HOME environment variable is not set.
    /// Will return `Err` if the aws config file cannot be read or parsed.
    #[instrument]
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = match (path, env_var("AWS_CONFIG_FILE")) {
            (Some(path), _) => PathBuf::from(path),
            (_, Ok(path)) => PathBuf::from(path),
            _ => dirs::home_dir().map_or_else(
                || Err(eyre!("The environment variable HOME must be set.")),
                |home_dir| Ok(home_dir.join(".aws").join("config")),
            )?,
        };

        let mut config = Ini::new();
        if path.exists() {
            config
                .load(&path)
                .map_err(|e| eyre!("Failed to load AWS config file: {}", e))?;
        }

        Ok(Self {
            path,
            config,
            profile_roles: HashMap::new(),
        })
    }

    /// Check if a profile is an SSO profile
    ///
    /// Returns true if the profile exists and has an `sso_session` field
    #[must_use]
    pub fn is_sso_profile(&self, profile_name: &str) -> bool {
        let section_name = format!("profile {profile_name}");
        self.config
            .get_map_ref()
            .get(&section_name)
            .and_then(|section| section.get("sso_session"))
            .and_then(|value| value.as_ref())
            .is_some()
    }

    /// Get the role for an existing profile
    ///
    /// Returns the current `sso_role_name` for the profile if it exists
    #[must_use]
    pub fn get_profile_role(&self, profile_name: &str) -> Option<String> {
        let section_name = format!("profile {profile_name}");
        self.config
            .get_map_ref()
            .get(&section_name)?
            .get("sso_role_name")?
            .clone()
    }

    /// Insert or update an SSO session
    ///
    /// # Errors
    ///
    /// Will return `Err` if the session name cannot be parsed
    pub fn upsert_sso_session(
        &mut self,
        session_name: &str,
        sso_start_url: &str,
        sso_region: &str,
    ) -> Result<()> {
        let section_name = format!("sso-session {session_name}");

        self.config.set(
            &section_name,
            "sso_start_url",
            Some(sso_start_url.to_string()),
        );
        self.config
            .set(&section_name, "sso_region", Some(sso_region.to_string()));
        self.config.set(
            &section_name,
            "sso_registration_scopes",
            Some("sso:account:access".to_string()),
        );

        Ok(())
    }

    /// Insert or update an SSO profile
    ///
    /// # Errors
    ///
    /// Will return `Err` if the profile name cannot be parsed
    pub fn upsert_sso_profile(
        &mut self,
        profile_name: &str,
        session_name: &str,
        account_id: &str,
        role_name: &str,
        available_roles: Vec<String>,
    ) -> Result<()> {
        let section_name = format!("profile {profile_name}");

        self.config
            .set(&section_name, "sso_session", Some(session_name.to_string()));
        self.config.set(
            &section_name,
            "sso_account_id",
            Some(account_id.to_string()),
        );
        self.config
            .set(&section_name, "sso_role_name", Some(role_name.to_string()));
        self.config
            .set(&section_name, "region", Some("us-east-1".to_string()));

        // Store available roles for this profile
        self.profile_roles
            .insert(profile_name.to_string(), available_roles);

        Ok(())
    }

    /// Write a section (sso-session or profile) to the output string
    fn write_section(&self, output: &mut String, section_name: &str) -> Result<()> {
        if let Some(section_map) = self.config.get_map_ref().get(section_name) {
            let mut keys: Vec<&String> = section_map.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(Some(value)) = section_map.get(key) {
                    writeln!(output, "{key} = {value}")?;
                }
            }
        }
        Ok(())
    }

    /// Write profile alternative roles as comments
    fn write_alternative_roles(
        &self,
        output: &mut String,
        profile_section: &str,
        current_role: &str,
    ) -> Result<()> {
        let profile_name = profile_section
            .strip_prefix("profile ")
            .unwrap_or(profile_section);
        if let Some(available_roles) = self.profile_roles.get(profile_name) {
            let other_roles: Vec<&String> = available_roles
                .iter()
                .filter(|role| role.as_str() != current_role)
                .collect();

            for role in other_roles {
                writeln!(output, "# sso_role_name = {role}")?;
            }
        }
        Ok(())
    }

    /// Write a profile section with its configuration and alternative role comments
    fn write_profile(&self, output: &mut String, profile_section: &str) -> Result<()> {
        writeln!(output)?;
        writeln!(output, "[{profile_section}]")?;

        if let Some(section_map) = self.config.get_map_ref().get(profile_section) {
            let mut keys: Vec<&String> = section_map.keys().collect();
            keys.sort();

            for key in keys {
                if let Some(Some(value)) = section_map.get(key) {
                    writeln!(output, "{key} = {value}")?;

                    // If this is sso_role_name, add commented alternatives
                    if key == "sso_role_name" {
                        self.write_alternative_roles(output, profile_section, value)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Save the config file to disk with smart formatting.
    ///
    /// The output is organized as follows:
    /// - SSO sessions are written first, sorted alphabetically
    /// - Each SSO session is followed by its associated profiles
    /// - Profiles within a session are sorted alphabetically
    /// - Non-SSO profiles are written at the end
    /// - Blank lines separate session groups
    /// - Alternative roles are shown as comments after `sso_role_name`
    ///
    /// # Errors
    ///
    /// Will return `Err` if the parent directory cannot be created.
    /// Will return `Err` if the config file cannot be written.
    #[instrument(skip_all)]
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write to a string first so we can add blank lines between sections and comment alternative roles
        let mut output = String::new();

        // Get all sections
        let sections: Vec<String> = self.config.sections().into_iter().collect();

        // Separate sso-session and profile sections
        let mut sso_sessions: Vec<String> = sections
            .iter()
            .filter(|s| s.starts_with("sso-session "))
            .cloned()
            .collect();
        sso_sessions.sort();

        let profile_sections: Vec<String> = sections
            .iter()
            .filter(|s| s.starts_with("profile "))
            .cloned()
            .collect();

        // Group profiles by their sso_session, and track profiles without sso_session
        let mut session_profiles: HashMap<String, Vec<String>> = HashMap::new();
        let mut non_sso_profiles: Vec<String> = Vec::new();
        for profile_section in &profile_sections {
            if let Some(section_map) = self.config.get_map_ref().get(profile_section) {
                if let Some(Some(session_name)) = section_map.get("sso_session") {
                    session_profiles
                        .entry(session_name.clone())
                        .or_default()
                        .push(profile_section.clone());
                } else {
                    non_sso_profiles.push(profile_section.clone());
                }
            }
        }
        non_sso_profiles.sort();

        // Write each sso-session followed by its profiles
        let mut first = true;
        for sso_session_section in &sso_sessions {
            // Add blank line between groups (but not before the first one)
            if !first {
                output.push('\n');
            }
            first = false;

            // Extract session name from "sso-session <name>"
            let session_name = sso_session_section
                .strip_prefix("sso-session ")
                .unwrap_or(sso_session_section);

            // Write the sso-session section
            writeln!(output, "[{sso_session_section}]")?;
            self.write_section(&mut output, sso_session_section)?;

            // Write all profiles for this session
            if let Some(profiles) = session_profiles.get(session_name) {
                let mut sorted_profiles = profiles.clone();
                sorted_profiles.sort();

                for profile_section in sorted_profiles {
                    self.write_profile(&mut output, &profile_section)?;
                }
            }
        }

        // Write non-SSO profiles at the end
        for profile_section in non_sso_profiles {
            if !first {
                writeln!(output)?;
            }
            first = false;

            writeln!(output, "[{profile_section}]")?;
            self.write_section(&mut output, &profile_section)?;
        }

        fs::write(&self.path, output).map_err(|e| eyre!("Failed to write AWS config file: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::Write;

    use tempfile::NamedTempFile;

    static CONFIG: &str = r"[profile existing]
region = us-west-2
output = json

[sso-session existing-session]
sso_start_url = https://existing.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access
";

    #[test]
    fn load_no_file() -> Result<()> {
        ConfigStore::load(Some(&PathBuf::from("THIS PATH DOES NOT EXIST")))?;
        Ok(())
    }

    #[test]
    fn insert_sso_session_empty_file() -> Result<()> {
        let tempfile = NamedTempFile::new()?;

        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        store.upsert_sso_session("my-sso", "https://my-org.awsapps.com/start", "us-east-1")?;

        store.save()?;

        let contents = fs::read_to_string(tempfile)?;
        eprintln!("Contents: {contents}");

        assert!(contents.contains("[sso-session my-sso]"));
        assert!(contents.contains("sso_start_url"));
        assert!(contents.contains("https://my-org.awsapps.com/start"));
        assert!(contents.contains("sso_region"));
        assert!(contents.contains("us-east-1"));
        assert!(contents.contains("sso_registration_scopes"));
        assert!(contents.contains("sso:account:access"));

        Ok(())
    }

    #[test]
    fn insert_sso_profile_empty_file() -> Result<()> {
        let tempfile = NamedTempFile::new()?;

        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        // Need to create the session first, then the profile
        store.upsert_sso_session("my-sso", "https://my-org.awsapps.com/start", "us-east-1")?;
        store.upsert_sso_profile(
            "my-profile",
            "my-sso",
            "123456789012",
            "MyRole",
            vec!["MyRole".to_string()],
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile)?;

        assert!(contents.contains("[profile my-profile]"));
        assert!(contents.contains("sso_session"));
        assert!(contents.contains("my-sso"));
        assert!(contents.contains("sso_account_id"));
        assert!(contents.contains("123456789012"));
        assert!(contents.contains("sso_role_name"));
        assert!(contents.contains("MyRole"));
        assert!(contents.contains("region"));
        assert!(contents.contains("us-east-1"));

        Ok(())
    }

    #[test]
    fn insert_sso_session_and_profile() -> Result<()> {
        let tempfile = NamedTempFile::new()?;

        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        store.upsert_sso_session("my-sso", "https://my-org.awsapps.com/start", "us-east-1")?;
        store.upsert_sso_profile(
            "my-profile",
            "my-sso",
            "123456789012",
            "MyRole",
            vec!["MyRole".to_string(), "OtherRole".to_string()],
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile)?;

        // Verify SSO session
        assert!(contents.contains("[sso-session my-sso]"));
        assert!(contents.contains("sso_start_url"));
        assert!(contents.contains("https://my-org.awsapps.com/start"));

        // Verify SSO profile
        assert!(contents.contains("[profile my-profile]"));
        assert!(contents.contains("sso_session"));
        assert!(contents.contains("my-sso"));

        Ok(())
    }

    #[test]
    fn update_existing_sso_session() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(tempfile, "{CONFIG}")?;

        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        store.upsert_sso_session(
            "existing-session",
            "https://new-url.awsapps.com/start",
            "us-west-2",
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile.path())?;

        assert!(contents.contains("sso_start_url"));
        assert!(contents.contains("https://new-url.awsapps.com/start"));
        assert!(contents.contains("sso_region"));
        assert!(contents.contains("us-west-2"));

        Ok(())
    }

    #[test]
    fn preserve_existing_profiles() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(tempfile, "{CONFIG}")?;

        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        // Create the SSO session first
        store.upsert_sso_session("my-sso", "https://my-sso.awsapps.com/start", "us-east-1")?;
        store.upsert_sso_profile(
            "new-profile",
            "my-sso",
            "123456789012",
            "MyRole",
            vec!["MyRole".to_string()],
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile.path())?;

        // Existing profile should still be there
        assert!(contents.contains("[profile existing]"));
        assert!(contents.contains("region"));
        assert!(contents.contains("us-west-2"));

        // New profile should be added
        assert!(contents.contains("[profile new-profile]"));
        assert!(contents.contains("sso_account_id"));
        assert!(contents.contains("123456789012"));

        Ok(())
    }

    #[test]
    fn test_is_sso_profile_with_sso_session() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;
        write!(
            tempfile,
            "[sso-session my-sso]\nsso_start_url = https://my.awsapps.com/start\nsso_region = us-east-1\n\n[profile sso-test]\nsso_session = my-sso\nsso_account_id = 123\nsso_role_name = Admin\n"
        )?;

        let store = ConfigStore::load(Some(tempfile.path()))?;
        assert!(store.is_sso_profile("sso-test"));
        Ok(())
    }

    #[test]
    fn test_is_sso_profile_without_sso_session() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;
        write!(
            tempfile,
            "[profile non-sso]\nregion = us-east-1\noutput = json\n"
        )?;

        let store = ConfigStore::load(Some(tempfile.path()))?;
        assert!(!store.is_sso_profile("non-sso"));
        Ok(())
    }

    #[test]
    fn test_is_sso_profile_non_existent() -> Result<()> {
        let tempfile = NamedTempFile::new()?;
        let store = ConfigStore::load(Some(tempfile.path()))?;
        assert!(!store.is_sso_profile("does-not-exist"));
        Ok(())
    }

    #[test]
    fn test_get_profile_role_existing() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;
        write!(
            tempfile,
            "[sso-session my-sso]\nsso_start_url = https://my.awsapps.com/start\n\n[profile test]\nsso_session = my-sso\nsso_role_name = AdminRole\n"
        )?;

        let store = ConfigStore::load(Some(tempfile.path()))?;
        assert_eq!(
            store.get_profile_role("test"),
            Some("AdminRole".to_string())
        );
        Ok(())
    }

    #[test]
    fn test_get_profile_role_non_existent() -> Result<()> {
        let tempfile = NamedTempFile::new()?;
        let store = ConfigStore::load(Some(tempfile.path()))?;
        assert_eq!(store.get_profile_role("does-not-exist"), None);
        Ok(())
    }

    #[test]
    fn test_get_profile_role_non_sso_profile() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;
        write!(tempfile, "[profile non-sso]\nregion = us-east-1\n")?;

        let store = ConfigStore::load(Some(tempfile.path()))?;
        assert_eq!(store.get_profile_role("non-sso"), None);
        Ok(())
    }

    #[test]
    fn test_multiple_sessions_with_profiles() -> Result<()> {
        let tempfile = NamedTempFile::new()?;
        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        // Create two sessions
        store.upsert_sso_session("session-a", "https://a.awsapps.com/start", "us-east-1")?;
        store.upsert_sso_session("session-b", "https://b.awsapps.com/start", "us-west-2")?;

        // Add profiles to each session
        store.upsert_sso_profile(
            "profile-a1",
            "session-a",
            "111111111111",
            "Admin",
            vec!["Admin".to_string()],
        )?;
        store.upsert_sso_profile(
            "profile-a2",
            "session-a",
            "222222222222",
            "ReadOnly",
            vec!["ReadOnly".to_string()],
        )?;
        store.upsert_sso_profile(
            "profile-b1",
            "session-b",
            "333333333333",
            "PowerUser",
            vec!["PowerUser".to_string()],
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile.path())?;

        // Verify sessions are present and alphabetically ordered
        let session_alpha_pos = contents
            .find("[sso-session session-a]")
            .expect("session-a not found");
        let session_beta_pos = contents
            .find("[sso-session session-b]")
            .expect("session-b not found");
        assert!(
            session_alpha_pos < session_beta_pos,
            "Sessions not in alphabetical order"
        );

        // Verify profiles are grouped with their sessions
        let profile_alpha1_pos = contents
            .find("[profile profile-a1]")
            .expect("profile-a1 not found");
        let profile_alpha2_pos = contents
            .find("[profile profile-a2]")
            .expect("profile-a2 not found");
        let profile_beta1_pos = contents
            .find("[profile profile-b1]")
            .expect("profile-b1 not found");

        // Profiles for session-a should come after session-a but before session-b
        assert!(session_alpha_pos < profile_alpha1_pos);
        assert!(profile_alpha1_pos < profile_alpha2_pos);
        assert!(profile_alpha2_pos < session_beta_pos);

        // Profile for session-b should come after session-b
        assert!(session_beta_pos < profile_beta1_pos);

        // Verify blank lines between groups
        let lines: Vec<&str> = contents.lines().collect();
        let mut found_blank_between_groups = false;
        for window in lines.windows(2) {
            if window[0].is_empty() && window[1].starts_with("[sso-session session-b]") {
                found_blank_between_groups = true;
                break;
            }
        }
        assert!(
            found_blank_between_groups,
            "No blank line between session groups"
        );

        Ok(())
    }

    #[test]
    fn test_role_alternatives_shown() -> Result<()> {
        let tempfile = NamedTempFile::new()?;
        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        store.upsert_sso_session("my-sso", "https://my.awsapps.com/start", "us-east-1")?;
        store.upsert_sso_profile(
            "multi-role",
            "my-sso",
            "123456789012",
            "Admin",
            vec![
                "Admin".to_string(),
                "ReadOnly".to_string(),
                "PowerUser".to_string(),
            ],
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile.path())?;

        // Should have active role
        assert!(contents.contains("sso_role_name = Admin"));
        // Should have commented alternatives
        assert!(contents.contains("# sso_role_name = PowerUser"));
        assert!(contents.contains("# sso_role_name = ReadOnly"));
        // Should NOT have the active role as a comment
        assert!(!contents.contains("# sso_role_name = Admin"));

        Ok(())
    }

    #[test]
    fn test_single_role_no_alternatives() -> Result<()> {
        let tempfile = NamedTempFile::new()?;
        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        store.upsert_sso_session("my-sso", "https://my.awsapps.com/start", "us-east-1")?;
        store.upsert_sso_profile(
            "single-role",
            "my-sso",
            "123456789012",
            "Admin",
            vec!["Admin".to_string()],
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile.path())?;

        // Should have active role
        assert!(contents.contains("sso_role_name = Admin"));
        // Should NOT have any commented alternatives
        assert!(!contents.contains("# sso_role_name"));

        Ok(())
    }

    #[test]
    fn test_empty_config_with_non_sso_profile() -> Result<()> {
        let tempfile = NamedTempFile::new()?;
        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        // Manually add a non-SSO profile
        store
            .config
            .set("profile test", "region", Some("us-west-2".to_string()));
        store
            .config
            .set("profile test", "output", Some("json".to_string()));

        store.save()?;

        let contents = fs::read_to_string(tempfile.path())?;

        // Should have the non-SSO profile
        assert!(contents.contains("[profile test]"));
        assert!(contents.contains("region = us-west-2"));
        assert!(contents.contains("output = json"));
        // Should not have sso_session field
        assert!(!contents.contains("sso_session"));

        Ok(())
    }

    #[test]
    fn test_sso_session_with_no_profiles() -> Result<()> {
        let tempfile = NamedTempFile::new()?;
        let mut store = ConfigStore::load(Some(tempfile.path()))?;

        // Create session with no profiles
        store.upsert_sso_session(
            "orphan-session",
            "https://orphan.awsapps.com/start",
            "us-east-1",
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile.path())?;

        // Session should still be written
        assert!(contents.contains("[sso-session orphan-session]"));
        assert!(contents.contains("sso_start_url"));

        Ok(())
    }
}
