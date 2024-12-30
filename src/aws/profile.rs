use aws_runtime::env_config::file::EnvConfigFileKind as ProfileFileKind;
use aws_runtime::env_config::file::EnvConfigFiles;
use aws_runtime::env_config::section::Section;
use aws_runtime::env_config::source::load as load_config_files;
use aws_runtime::env_config::section::Profile;
use aws_runtime::env_config::section::EnvConfigSections;
use aws_runtime::env_config::property::Property;
use aws_credential_types::Credentials;
use aws_types::os_shim_internal::{Env, Fs};
use dirs;
use eyre::Context;
use eyre::{eyre, Result};
use itertools::Itertools;
use std::collections::HashMap;
use std::env::var as env_var;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::instrument;

trait ToIni {
    fn to_ini(&self) -> String;
}

impl<T: Section> ToIni for &T {
    fn to_ini(&self) -> String {
        let mut ini = String::new();

        ini.push_str(&format!("[{}]\n", self.name()));

        for property in self.properties().keys().sorted() {
            ini.push_str(&format!("{}={}\n", property, self.properties().get(property).unwrap().value()));
        }

        ini
    }
}

impl ToIni for EnvConfigSections {
    fn to_ini(&self) -> String {
        let mut ini = String::new();

        for profile in self.profiles().sorted() {
            ini.push_str(&self.get_profile(profile).unwrap().to_ini());
            ini.push_str("\n");
        }

        for sso_session in self.sso_sessions().sorted() {
            ini.push_str(&self.sso_session(sso_session).unwrap().to_ini());
            ini.push_str("\n");
        }

        for key in self.other_sections().keys().sorted() {
            ini.push_str(&format!("{}={}\n", key, self.other_sections().get(key).unwrap()));
        }

        ini
    }
}

#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    profiles: EnvConfigSections,
}

impl Store {
    #[instrument]
    pub async fn load(path: Option<&Path>) -> Result<Self> {
        let path = match (path, env_var("AWS_SHARED_CREDENTIALS_FILE")) {
            (Some(path), _) => PathBuf::from(path),
            (None, Ok(path)) => PathBuf::from(path),
            (None, Err(_)) => Self::default_location()?,
        };

        let mut profile_files = EnvConfigFiles::builder();
        if path.exists() {
            profile_files = profile_files.with_file(ProfileFileKind::Credentials, &path);
        } else {
            // Dummy credentials
            profile_files = profile_files.with_contents(ProfileFileKind::Credentials, "");
        }

        let config_file = load_config_files(&Env::default(), &Fs::default(), &profile_files.build()).await?;
        let profiles = EnvConfigSections::parse(config_file).context("could not parse profile file")?;

        Ok(Self { path, profiles })
    }

    /// # Errors
    ///
    /// Will return Err if the credentials provided are not STS.
    /// Will return Err if the current credentials for the profile are not STS.
    pub fn upsert_credential(&mut self, profile_name: &str, creds: &Credentials) -> Result<()> {
        if self.profiles.get_profile(profile_name).is_none() {
            self.profiles
                .insert_profile(Profile::new(profile_name.to_string(), HashMap::new()));
        };

        let profile = self
            .profiles
            .get_profile_mut(profile_name)
            .ok_or_else(|| eyre!("Could not find profile: {profile_name}"))?;

        if profile.get("aws_access_key_id").is_some()
            && profile.get("aws_secret_access_key").is_some()
            && profile.get("aws_session_token").is_none()
        {
            return Err(eyre!(
                "The credentials for {profile_name} are not STS. Refusing to overwrite them"
            ));
        }

        profile.insert(String::from("aws_access_key_id"), Property::new(String::from("aws_access_key_id"), creds.access_key_id().to_string()));
        profile.insert(String::from("aws_secret_access_key"), Property::new(String::from("aws_secret_access_key"), creds.secret_access_key().to_string()));
        profile.insert(
            String::from("aws_session_token"),
            Property::new(String::from("aws_session_token"),
            creds
                .session_token()
                .ok_or_else(|| eyre!("No session token found for {profile_name}"))?
                .to_string()
            )
        );

        Ok(())
    }

    #[instrument(skip_all)]
    pub fn save(&self) -> Result<()> {
        let ini = self.profiles.to_ini();

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.path, ini).map_err(Into::into)
    }

    fn default_location() -> Result<PathBuf> {
        dirs::home_dir().map_or_else(
            || Err(eyre!("The environment variable HOME must be set.")),
            |home_dir| Ok(home_dir.join(".aws").join("credentials")),
        )
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
    fn create_new_store() -> Result<()> {
        let tmp_dir = tempfile::tempdir()?;

        let mut store = tokio_test::block_on(async {
            Store::load(Some(&tmp_dir.path().join(".aws").join("credentials")))
                .await
                .unwrap()
        });

        store
            .profiles
            .insert_profile(Profile::new("mock-profile".to_string(), HashMap::new()));

        store.save()
    }

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

        let store =
            tokio_test::block_on(async { Store::load(Some(tempfile.path())).await.unwrap() });
        let profile = store.profiles.get_profile("example").unwrap();

        assert_eq!(profile.get("aws_access_key_id"), Some("ACCESS_KEY"));
        assert_eq!(
            profile.get("aws_secret_access_key"),
            Some("SECRET_ACCESS_KEY")
        );
        assert_eq!(profile.get("aws_session_token"), Some("SESSION_TOKEN"));
        assert_eq!(profile.get("foo"), Some("bar"));

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

        let store =
            tokio_test::block_on(async { Store::load(Some(tempfile.path())).await.unwrap() });
        let profile = store.profiles.get_profile("example").unwrap();

        assert_eq!(profile.get("aws_access_key_id"), Some("ACCESS_KEY_1"));
        assert_eq!(
            profile.get("aws_secret_access_key"),
            Some("\"SECRET_ACCESS_KEY_1\"")
        );
        assert_eq!(profile.get("aws_session_token"), Some("'SESSION_TOKEN_1'"));

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

        let mut store =
            tokio_test::block_on(async { Store::load(Some(tempfile.path())).await.unwrap() });

        store.upsert_credential(
            "example",
            &Credentials::new(
                "NEW_ACCESS_KEY",
                "NEW_SECRET_ACCESS_KEY",
                Some("NEW_SESSION_TOKEN".to_string()),
                None,
                "oktaws",
            ),
        )?;

        let profile = store.profiles.get_profile("example").unwrap();

        assert_eq!(profile.get("aws_access_key_id"), Some("NEW_ACCESS_KEY"));
        assert_eq!(
            profile.get("aws_secret_access_key"),
            Some("NEW_SECRET_ACCESS_KEY")
        );
        assert_eq!(profile.get("aws_session_token"), Some("NEW_SESSION_TOKEN"));

        Ok(())
    }

    #[test]
    fn insert_credentials() -> Result<()> {
        // This also tests file not existing
        let tempfile = NamedTempFile::new()?;

        let mut store =
            tokio_test::block_on(async { Store::load(Some(tempfile.path())).await.unwrap() });

        store.upsert_credential(
            "example",
            &Credentials::new(
                "NEW_ACCESS_KEY",
                "NEW_SECRET_ACCESS_KEY",
                Some("NEW_SESSION_TOKEN".to_string()),
                None,
                "oktaws",
            ),
        )?;

        let profile = store.profiles.get_profile("example").unwrap();

        assert_eq!(profile.get("aws_access_key_id"), Some("NEW_ACCESS_KEY"));
        assert_eq!(
            profile.get("aws_secret_access_key"),
            Some("NEW_SECRET_ACCESS_KEY")
        );
        assert_eq!(profile.get("aws_session_token"), Some("NEW_SESSION_TOKEN"));

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

        let mut store =
            tokio_test::block_on(async { Store::load(Some(tempfile.path())).await.unwrap() });

        let err = store
            .upsert_credential(
                "example",
                &Credentials::new(
                    "NEW_ACCESS_KEY",
                    "NEW_SECRET_ACCESS_KEY",
                    Some("NEW_SESSION_TOKEN".to_string()),
                    None,
                    "oktaws",
                ),
            )
            .unwrap_err();

        assert_eq!(
            format!("{err:?}"),
            format!(
                "The credentials for example are not STS. Refusing to overwrite them

Location:
    {}:108:24",
                PathBuf::from_iter(["src", "aws", "profile.rs"]).display()
            ),
        );

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

        let err =
            tokio_test::block_on(async { Store::load(Some(tempfile.path())).await.err().unwrap() });

        assert_eq!(
            format!("{err:?}"),
            format!(
                "could not parse profile file

Caused by:
    error parsing {} on line 4:
      Expected an '=' sign defining a property

Location:
    {}:84:62",
                tempfile.path().display(),
                PathBuf::from_iter(["src", "aws", "profile.rs"]).display()
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

        let err =
            tokio_test::block_on(async { Store::load(Some(tempfile.path())).await.err().unwrap() });

        assert_eq!(
            format!("{err:?}"),
            format!(
                "could not parse profile file

Caused by:
    error parsing {} on line 4:
      Expected an '=' sign defining a property

Location:
    {}:84:62",
                tempfile.path().display(),
                PathBuf::from_iter(["src", "aws", "profile.rs"]).display()
            )
        );

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
# This comment is important
bar=baz

[example_static]
aws_secret_access_key=SECRET_ACCESS_KEY
aws_access_key_id=ACCESS_KEY
foo=bar"#
        )?;

        let mut store =
            tokio_test::block_on(async { Store::load(Some(tempfile.path())).await.unwrap() });

        store.upsert_credential(
            "example_sts",
            &Credentials::new(
                "NEW_ACCESS_KEY",
                "NEW_SECRET_ACCESS_KEY",
                Some("NEW_SESSION_TOKEN".to_string()),
                None,
                "oktaws",
            ),
        )?;

        store.save()?;

        let credentials = fs::read_to_string(tempfile)?;

        dbg!(&credentials);

        // These are line by line to avoid OS-specific line-endings
        let mut lines = credentials.lines();
        assert_eq!(lines.next(), Some("[example_static]"));
        assert_eq!(lines.next(), Some("aws_access_key_id=ACCESS_KEY"));
        assert_eq!(
            lines.next(),
            Some("aws_secret_access_key=SECRET_ACCESS_KEY")
        );
        assert_eq!(lines.next(), Some("foo=bar"));
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.next(), Some("[example_sts]"));
        assert_eq!(lines.next(), Some("aws_access_key_id=NEW_ACCESS_KEY"));
        assert_eq!(
            lines.next(),
            Some("aws_secret_access_key=NEW_SECRET_ACCESS_KEY")
        );
        assert_eq!(lines.next(), Some("aws_session_token=NEW_SESSION_TOKEN"));
        assert_eq!(lines.next(), Some("bar=baz"));
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.next(), None);

        Ok(())
    }
}
