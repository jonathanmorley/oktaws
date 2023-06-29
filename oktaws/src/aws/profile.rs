use aws_config::profile;
use aws_config::profile::profile_file::{ProfileFileKind, ProfileFiles};
use aws_config::profile::{Profile, ProfileSet};
use aws_credential_types::Credentials;
use aws_types::os_shim_internal::{Env, Fs};
use dirs;
use eyre::{eyre, Result};
use path_abs::PathFile;
use std::collections::HashMap;
use std::env::var as env_var;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::instrument;

#[derive(Debug)]
pub struct Store {
    path: PathFile,
    profiles: ProfileSet,
}

impl Store {
    #[instrument]
    pub async fn load(path: Option<&Path>) -> Result<Self> {
        let path = match (path, env_var("AWS_SHARED_CREDENTIALS_FILE")) {
            (Some(path), _) => PathBuf::from(path),
            (None, Ok(path)) => PathBuf::from(path),
            (None, Err(_)) => Self::default_location()?,
        };

        let profile_files = ProfileFiles::builder()
            .with_file(ProfileFileKind::Credentials, &path)
            .build();

        let profiles = profile::load(&Fs::default(), &Env::default(), &profile_files, None).await?;

        Ok(Self {
            path: PathFile::create(path)?,
            profiles,
        })
    }

    /// # Errors
    ///
    /// Will return Err if the credentials provided are not STS.
    /// Will return Err if the current credentials for the profile are not STS.
    pub fn upsert_credential(&mut self, profile_name: &str, creds: &Credentials) -> Result<()> {
        if self.profiles.get_profile(profile_name).is_none() {
            self.profiles
                .set_profile(Profile::new(profile_name.to_string(), HashMap::new()));
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

        profile.set("aws_access_key_id", creds.access_key_id());
        profile.set("aws_secret_access_key", creds.secret_access_key());
        profile.set(
            "aws_session_token",
            creds
                .session_token()
                .ok_or_else(|| eyre!("No session token found for {profile_name}"))?,
        );

        Ok(())
    }

    #[instrument(skip_all)]
    pub fn save(&self) -> Result<()> {
        let credentials = self.profiles.to_string(ProfileFileKind::Credentials);
        fs::write(&self.path, credentials).map_err(Into::into)
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
            "The credentials for example are not STS. Refusing to overwrite them

Location:
    oktaws/src/aws/profile.rs:61:24",
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
    oktaws/src/aws/profile.rs:34:24",
                normalize(tempfile.path())
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
    oktaws/src/aws/profile.rs:34:24",
                normalize(tempfile.path())
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
        assert_eq!(lines.next(), None);

        Ok(())
    }

    /// For some reason, windows paths go through some canonicalization step
    /// when used in errors.
    ///
    /// This is to emulate this behaviour during testing
    fn normalize<P: AsRef<Path>>(p: P) -> String {
        let path = p.as_ref();

        #[cfg(target_os = "windows")]
        {
            format!(r"\\?\{}", path.to_string_lossy())
        }

        #[cfg(not(target_os = "windows"))]
        {
            path.to_string_lossy().into_owned()
        }
    }
}
