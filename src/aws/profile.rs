use aws_config_mod::{AwsCredentialsFile, Value};
use aws_credential_types::Credentials;
use dirs;
use eyre::{eyre, Context, Result};
use std::env::var as env_var;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::instrument;

#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    credentials_file: AwsCredentialsFile,
}

impl Store {
    #[instrument]
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = match (path, env_var("AWS_SHARED_CREDENTIALS_FILE")) {
            (Some(path), _) => PathBuf::from(path),
            (_, Ok(path)) => PathBuf::from(path),
            _ => dirs::home_dir().map_or_else(
                || Err(eyre!("The environment variable HOME must be set.")),
                |home_dir| Ok(home_dir.join(".aws").join("credentials")),
            )?,
        };

        let credentials_file = if path.exists() {
            fs::read_to_string(&path)?.parse().wrap_err_with(|| {
                format!("Failed to parse AWS credentials file {}", &path.display())
            })?
        } else {
            AwsCredentialsFile::default()
        };

        Ok(Self {
            path,
            credentials_file,
        })
    }

    /// # Errors
    ///
    /// Will return Err if the credentials provided are not STS.
    /// Will return Err if the current credentials for the profile are not STS.
    pub fn upsert_credential(&mut self, profile_name: &str, creds: &Credentials) -> Result<()> {
        let profile = self.credentials_file.insert_profile(profile_name.parse()?);

        let access_key_id = profile.get_setting(&"aws_access_key_id".parse()?);
        let secret_access_key_name = profile.get_setting(&"aws_secret_access_key".parse()?);
        let session_token_name = profile.get_setting(&"aws_session_token".parse()?);

        if access_key_id.is_some()
            && secret_access_key_name.is_some()
            && session_token_name.is_none()
        {
            return Err(eyre!(
                "The credentials for {profile_name} are not STS. Refusing to overwrite them"
            ));
        }

        profile.set(
            "aws_access_key_id".parse()?,
            Value::from(creds.access_key_id()),
        );
        profile.set(
            "aws_secret_access_key".parse()?,
            Value::from(creds.secret_access_key()),
        );
        if let Some(session_token) = creds.session_token() {
            profile.set("aws_session_token".parse()?, Value::from(session_token));
        } else {
            return Err(eyre!("No session token found for {profile_name}"));
        }

        Ok(())
    }

    #[instrument(skip_all)]
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.path, self.credentials_file.to_string()).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::Write;

    use itertools::Itertools;
    use tempfile;
    use tempfile::NamedTempFile;

    static CREDENTIALS: &str = r#"[foo]
# This is an important comment
# Extra whitespace is allowed
aws_access_key_id =                FOO_ACCESS_KEY

# Mixed quotes and unordered fields are allowed
aws_session_token = 'FOO_SESSION_TOKEN'
# Less whitespace is allowed
aws_secret_access_key="FOO_SECRET_ACCESS_KEY"
# Extra fields are allowed, but will be ignored
foo=bar

[static]
# This profile is not STS, and should not be changed
aws_access_key_id = STATIC_ACCESS_KEY
aws_secret_access_key = STATIC_SECRET_ACCESS_KEY
"#;

    #[test]
    fn load_no_file() -> Result<()> {
        Store::load(Some(&PathBuf::from("THIS PATH DOES NOT EXIST")))?;
        Ok(())
    }

    #[test]
    fn insert_credential_empty_file() -> Result<()> {
        let tempfile = NamedTempFile::new()?;

        let mut store = Store::load(Some(tempfile.path()))?;

        store.upsert_credential(
            "foo",
            &Credentials::new(
                "NEW_FOO_ACCESS_KEY",
                "NEW_FOO_SECRET_ACCESS_KEY",
                Some("NEW_FOO_SESSION_TOKEN".to_string()),
                None,
                "oktaws",
            ),
        )?;

        store.upsert_credential(
            "bar",
            &Credentials::new(
                "NEW_BAR_ACCESS_KEY",
                "NEW_BAR_SECRET_ACCESS_KEY",
                Some("NEW_BAR_SESSION_TOKEN".to_string()),
                None,
                "oktaws",
            ),
        )?;

        store.save()?;

        let contents = fs::read_to_string(tempfile)?;

        // These are line by line to avoid OS-specific line-endings
        let mut lines = contents.lines();
        assert_eq!(lines.next(), Some("[foo]"));
        assert_eq!(lines.next(), Some("aws_access_key_id = NEW_FOO_ACCESS_KEY"));
        assert_eq!(
            lines.next(),
            Some("aws_secret_access_key = NEW_FOO_SECRET_ACCESS_KEY")
        );
        assert_eq!(
            lines.next(),
            Some("aws_session_token = NEW_FOO_SESSION_TOKEN")
        );
        assert_eq!(lines.next(), Some("[bar]"));
        assert_eq!(lines.next(), Some("aws_access_key_id = NEW_BAR_ACCESS_KEY"));
        assert_eq!(
            lines.next(),
            Some("aws_secret_access_key = NEW_BAR_SECRET_ACCESS_KEY")
        );
        assert_eq!(
            lines.next(),
            Some("aws_session_token = NEW_BAR_SESSION_TOKEN")
        );
        assert_eq!(lines.next(), None);

        Ok(())
    }

    #[test]
    fn insert_credential_existing_file() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(tempfile, "{CREDENTIALS}")?;

        let mut store = Store::load(Some(tempfile.path()))?;

        store.upsert_credential(
            "example",
            &Credentials::new(
                "NEW_EXAMPLE_ACCESS_KEY",
                "NEW_EXAMPLE_SECRET_ACCESS_KEY",
                Some("NEW_EXAMPLE_SESSION_TOKEN".to_string()),
                None,
                "oktaws",
            ),
        )?;

        store.save()?;

        // Normalize line endings to avoid OS-specifics
        let contents = fs::read_to_string(tempfile.path())?.lines().join("\n");

        assert_eq!(
            contents,
            format!(
                r"{}
[example]
aws_access_key_id = NEW_EXAMPLE_ACCESS_KEY
aws_secret_access_key = NEW_EXAMPLE_SECRET_ACCESS_KEY
aws_session_token = NEW_EXAMPLE_SESSION_TOKEN",
                CREDENTIALS.trim_end()
            )
            .as_str()
        );

        Ok(())
    }

    #[test]
    fn update_existing_credential() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(tempfile, "{CREDENTIALS}")?;

        let mut store = Store::load(Some(tempfile.path()))?;

        store.upsert_credential(
            "foo",
            &Credentials::new(
                "NEW_FOO_ACCESS_KEY",
                "NEW_FOO_SECRET_ACCESS_KEY",
                Some("NEW_FOO_SESSION_TOKEN".to_string()),
                None,
                "oktaws",
            ),
        )?;

        store.save()?;

        // Normalize line endings to avoid OS-specifics
        let contents = fs::read_to_string(tempfile.path())?.lines().join("\n");

        // Whitespace is preserved (except trailing whitespace), quotes are removed
        assert_eq!(
            contents,
            r"[foo]
# This is an important comment
# Extra whitespace is allowed
aws_access_key_id =                NEW_FOO_ACCESS_KEY

# Mixed quotes and unordered fields are allowed
aws_session_token = NEW_FOO_SESSION_TOKEN
# Less whitespace is allowed
aws_secret_access_key=NEW_FOO_SECRET_ACCESS_KEY
# Extra fields are allowed, but will be ignored
foo=bar

[static]
# This profile is not STS, and should not be changed
aws_access_key_id = STATIC_ACCESS_KEY
aws_secret_access_key = STATIC_SECRET_ACCESS_KEY"
        );

        Ok(())
    }

    #[test]
    fn not_update_creds_on_static_profile() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(tempfile, "{CREDENTIALS}")?;

        let mut store = Store::load(Some(tempfile.path()))?;

        let err = store
            .upsert_credential(
                "static",
                &Credentials::new(
                    "NEW_STATIC_ACCESS_KEY",
                    "NEW_STATIC_ACCESS_KEY",
                    Some("NEW_STATIC_SESSION_TOKEN".to_string()),
                    None,
                    "oktaws",
                ),
            )
            .unwrap_err();

        assert_eq!(
            format!("{err:?}"),
            format!(
                "The credentials for static are not STS. Refusing to overwrite them

Location:
    {}:57:24",
                PathBuf::from_iter(["src", "aws", "profile.rs"]).display()
            ),
        );

        store.save()?;

        // Normalize line endings to avoid OS-specifics
        let contents = fs::read_to_string(tempfile.path())?.lines().join("\n");

        assert_eq!(contents, CREDENTIALS.trim_end());

        Ok(())
    }

    #[test]
    fn parse_bad_ini() -> Result<()> {
        let mut tempfile = NamedTempFile::new()?;

        write!(
            tempfile,
            r"[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
foo"
        )?;

        let err = Store::load(Some(tempfile.path())).unwrap_err();

        assert_eq!(
            format!("{err:?}"),
            format!(
                "Failed to parse AWS credentials file {}

Caused by:
   0: Failed to parse config file:
      \tParsing Error: VerboseError {{ errors: [(\"foo\", Nom(Eof))] }}
   1: Parsing Error: VerboseError {{ errors: [(\"foo\", Nom(Eof))] }}

Location:
    {}:29:48",
                tempfile.path().display(),
                PathBuf::from_iter(["src", "aws", "profile.rs"]).display()
            )
        );

        Ok(())
    }
}
