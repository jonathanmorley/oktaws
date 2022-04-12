use std::env::var as env_var;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aws_types::Credentials;
use dirs;
use ini::{Ini, Properties, SectionEntry};
use path_abs::PathFile;
use tracing::instrument;

pub struct CredentialsStore {
    path: PathFile,
    profiles: Ini,
}

impl CredentialsStore {
    #[instrument]
    pub fn load(path: Option<&Path>) -> Result<CredentialsStore> {
        let path = match (path, env_var("AWS_SHARED_CREDENTIALS_FILE")) {
            (Some(path), _) => PathBuf::from(path),
            (None, Ok(path)) => PathBuf::from(path),
            (None, Err(_)) => CredentialsStore::default_location()?,
        };

        let path = PathFile::create(path)?;
        let profiles =
            Ini::load_from_file(&path).with_context(|| format!("Unable to parse {path:?}"))?;

        let store = CredentialsStore { path, profiles };
        store
            .validate()
            .with_context(|| format!("Unable to validate {:?}", store.path))?;

        Ok(store)
    }

    pub fn upsert_credential(&mut self, profile: &str, creds: Credentials) {
        self.profiles.set_to(
            Some(profile),
            "aws_access_key_id".into(),
            creds.access_key_id().into(),
        );
        self.profiles.set_to(
            Some(profile),
            "aws_secret_access_key".into(),
            creds.secret_access_key().into(),
        );

        if let Some(session_token) = creds.session_token() {
            self.profiles.set_to(
                Some(profile),
                "aws_session_token".into(),
                session_token.into(),
            );
        }
    }

    pub fn read_profile(&self, profile: &str) -> Option<&Properties> {
        self.profiles.section(Some(profile))
    }

    #[instrument(skip_all)]
    pub fn save(&self) -> Result<()> {
        self.profiles.write_to_file(&self.path).map_err(Into::into)
    }

    fn validate(&self) -> Result<()> {
        for section in self.profiles.sections() {
            if let Some(props) = self.profiles.section(section) {
                for (key, _) in props.iter() {
                    if key.contains("\n") {
                        return Err(anyhow!(
                            "Key {key:?} in Section {section:?} must not contain '\\n'"
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn default_location() -> Result<PathBuf> {
        match dirs::home_dir() {
            Some(home_dir) => Ok(home_dir.join(".aws").join("credentials")),
            None => Err(anyhow!("The environment variable HOME must be set.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::Write;

    use tempfile;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_profile_with_extra_fields() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(
            tempfile,
            "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN
foo=bar"
        )?;

        let credentials = CredentialsStore::load(Some(tempfile.path()))?;
        let profile = credentials.read_profile("example").unwrap();

        assert_eq!(&profile["aws_access_key_id"], "ACCESS_KEY");
        assert_eq!(&profile["aws_secret_access_key"], "SECRET_ACCESS_KEY");
        assert_eq!(&profile["aws_session_token"], "SESSION_TOKEN");
        assert_eq!(&profile["foo"], "bar");

        Ok(())
    }

    #[test]
    fn parse_mixed_quotes_spaces() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(
            tempfile,
            r#"
[example]
aws_access_key_id = ACCESS_KEY_1
aws_secret_access_key="SECRET_ACCESS_KEY_1"
aws_session_token='SESSION_TOKEN_1'"#
        )?;

        let credentials = CredentialsStore::load(Some(tempfile.path()))?;
        let profile = credentials.read_profile("example").unwrap();

        assert_eq!(&profile["aws_access_key_id"], "ACCESS_KEY_1");
        assert_eq!(&profile["aws_secret_access_key"], "SECRET_ACCESS_KEY_1");
        assert_eq!(&profile["aws_session_token"], "SESSION_TOKEN_1");

        Ok(())
    }

    #[test]
    fn update_credential() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(
            tempfile,
            r#"[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN
foo=bar"#
        )?;

        let mut credentials = CredentialsStore::load(Some(tempfile.path()))?;

        credentials.upsert_credential(
            "example",
            Credentials::from_keys(
                "NEW_ACCESS_KEY",
                "NEW_SECRET_ACCESS_KEY",
                Some("NEW_SESSION_TOKEN".to_string()),
            ),
        );

        let profile = credentials.read_profile("example").unwrap();

        assert_eq!(&profile["aws_access_key_id"], "NEW_ACCESS_KEY");
        assert_eq!(&profile["aws_secret_access_key"], "NEW_SECRET_ACCESS_KEY");
        assert_eq!(&profile["aws_session_token"], "NEW_SESSION_TOKEN");

        Ok(())
    }

    #[test]
    fn insert_credentials() -> Result<()> {
        // This also tests file not existing
        let tempfile = NamedTempFile::new()?;

        let mut credentials = CredentialsStore::load(Some(tempfile.path()))?;

        credentials.upsert_credential(
            "example",
            Credentials::from_keys(
                "NEW_ACCESS_KEY".to_string(),
                "NEW_SECRET_ACCESS_KEY".to_string(),
                Some("NEW_SESSION_TOKEN".to_string()),
            ),
        );

        let profile = credentials.read_profile("example").unwrap();

        assert_eq!(&profile["aws_access_key_id"], "NEW_ACCESS_KEY");
        assert_eq!(&profile["aws_secret_access_key"], "NEW_SECRET_ACCESS_KEY");
        assert_eq!(&profile["aws_session_token"], "NEW_SESSION_TOKEN");

        Ok(())
    }

    #[test]
    fn update_creds_on_non_sts_profile() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(
            tempfile,
            r#"[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
foo=bar"#
        )?;

        let mut credentials = CredentialsStore::load(Some(tempfile.path()))?;

        credentials.upsert_credential(
            "example",
            Credentials::from_keys(
                "NEW_ACCESS_KEY".to_string(),
                "NEW_SECRET_ACCESS_KEY".to_string(),
                Some("NEW_SESSION_TOKEN".to_string()),
            ),
        );

        let profile = credentials.read_profile("example").unwrap();

        assert_eq!(&profile["aws_access_key_id"], "NEW_ACCESS_KEY");
        assert_eq!(&profile["aws_secret_access_key"], "NEW_SECRET_ACCESS_KEY");
        assert_eq!(&profile["aws_session_token"], "NEW_SESSION_TOKEN");
        assert_eq!(&profile["foo"], "bar");

        Ok(())
    }

    #[test]
    fn parse_bad_ini() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(
            tempfile,
            r#"[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
foo"#
        )?;

        let err = CredentialsStore::load(Some(tempfile.path())).err().unwrap();

        assert_eq!(
            format!("{err:?}"),
            format!(
                "Unable to parse \"{}\"

Caused by:
    3:3 expecting \"[Some('='), Some(':')]\" but found EOF.",
                tempfile.path().to_string_lossy()
            )
        );

        Ok(())
    }

    #[test]
    fn parse_bad_ini_followed_by_good_ini() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(
            tempfile,
            r#"[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
foo

[example2]
aws_access_key_id=ACCESS_KEY2
aws_secret_access_key=SECRET_ACCESS_KEY2"#
        )?;

        let err = CredentialsStore::load(Some(tempfile.path())).err().unwrap();

        assert_eq!(format!("{err:?}"), format!("Unable to validate \"{}\"

Caused by:
    Key \"foo\\n\\n[example2]\\naws_access_key_id\" in Section Some(\"example\") must not contain '\\n'", tempfile.path().to_string_lossy()));

        Ok(())
    }

    #[test]
    fn roundtrip_with_update() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        // This also checks that non-alphabetical ordering is preserved.
        // Comments are not currently preserved
        write!(
            tempfile,
            r#"[example_sts]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN
# This is important
bar=baz

[example_static]
aws_secret_access_key=SECRET_ACCESS_KEY
aws_access_key_id=ACCESS_KEY
foo=bar"#
        )?;

        let mut credentials = CredentialsStore::load(Some(tempfile.path()))?;

        credentials.upsert_credential(
            "example_sts",
            Credentials::from_keys(
                "NEW_ACCESS_KEY".to_string(),
                "NEW_SECRET_ACCESS_KEY".to_string(),
                Some("NEW_SESSION_TOKEN".to_string()),
            ),
        );

        credentials.save()?;

        let credentials = fs::read_to_string(tempfile)?;

        assert_eq!(
            credentials,
            "[example_sts]
bar=baz
aws_access_key_id=NEW_ACCESS_KEY
aws_secret_access_key=NEW_SECRET_ACCESS_KEY
aws_session_token=NEW_SESSION_TOKEN

[example_static]
aws_secret_access_key=SECRET_ACCESS_KEY
aws_access_key_id=ACCESS_KEY
foo=bar
"
        );

        Ok(())
    }
}
