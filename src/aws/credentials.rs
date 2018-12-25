//! The Credentials Provider for Credentials stored in a profile inside of a Credentials file.
//! Adapted from https://raw.githubusercontent.com/rusoto/rusoto/master/rusoto/credential/src/profile.rs

use failure::Error;
use path_abs::{FileEdit, FileRead, PathFile, FileWrite};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::env::var as env_var;
use std::fs::File;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use try_from::{TryFrom, TryInto};
use serde_ini;
use std::fmt;

use dirs::home_dir;
use regex::Regex;

use rusoto_credential::{AwsCredentials, CredentialsError};
use rusoto_sts::Credentials as StsCredentials;

const AWS_SHARED_CREDENTIALS_FILE: &str = "AWS_SHARED_CREDENTIALS_FILE";

pub struct CredentialsFile {
    file_path: PathFile,
    credentials: CredentialProfiles,
}

impl TryFrom<PathBuf> for CredentialsFile {
    type Err = Error;

    fn try_from(file_path: PathBuf) -> Result<Self, Self::Err> {
        Ok(CredentialsFile {
            credentials: FileRead::read(&file_path)?.read_string()?.parse()?,
            file_path: PathFile::create(file_path)?,
        })
    }
}

impl CredentialsFile {
    pub fn new(path: Option<PathBuf>) -> Result<CredentialsFile, Error> {
        match path {
            Some(path) => path.try_into(),
            None => default_location()?.try_into()
        }
    }

    pub fn set_profile<S, C>(&mut self, name: S, creds: C) -> Result<(), Error> where S: Into<String>, C: Into<AwsCredentials> {
        self.credentials.set_profile(name, creds)
    }

    pub fn set_profile_sts<S, C>(&mut self, name: S, creds: C) -> Result<(), Error> where S: Into<String>, C: Into<StsCredentials> {
        self.credentials.set_profile_sts(name, creds)
    }

    pub fn save(self) -> Result<(), Error> {
        FileWrite::create(self.file_path)?.write_str(&format!("{}", self.credentials)).map_err(|e| e.into())
    }
}

/// Default credentials file location:
/// 1. if set and not empty, use value from environment variable ```AWS_SHARED_CREDENTIALS_FILE```
/// 2. otherwise return `~/.aws/credentials` (Linux/Mac) resp. `%USERPROFILE%\.aws\credentials` (Windows)
pub fn default_location() -> Result<PathBuf, CredentialsError> {
    let env = env_var(AWS_SHARED_CREDENTIALS_FILE)
        .ok()
        .filter(|e| !e.is_empty());
    match env {
        Some(path) => Ok(PathBuf::from(path)),
        None => hardcoded_location(),
    }
}

fn hardcoded_location() -> Result<PathBuf, CredentialsError> {
    match home_dir() {
        Some(mut home_path) => {
            home_path.push(".aws");
            home_path.push("credentials");
            Ok(home_path)
        }
        None => Err(CredentialsError::new("Failed to determine home directory.")),
    }
}

// should probably constantize with lazy_static!
fn new_profile_regex() -> Regex {
    Regex::new(r"^\[([^\]]+)\]$").expect("Failed to compile regex")
}

struct CredentialProfiles(BTreeMap<String, AwsCredentials>);

impl FromStr for CredentialProfiles {
    type Err = CredentialsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let profile_regex = new_profile_regex();
        let mut profiles: BTreeMap<String, AwsCredentials> = BTreeMap::new();
        let mut access_key: Option<String> = None;
        let mut secret_key: Option<String> = None;
        let mut token: Option<String> = None;
        let mut profile_name: Option<String> = None;

        for line in s.lines() {
            // skip empty lines
            if line.is_empty() {
                continue;
            }

            // skip comments
            if line.starts_with('#') {
                continue;
            }

            // handle the opening of named profile blocks
            if profile_regex.is_match(&line) {
                if profile_name.is_some() && access_key.is_some() && secret_key.is_some() {
                    let creds =
                        AwsCredentials::new(access_key.unwrap(), secret_key.unwrap(), token, None);
                    profiles.insert(profile_name.unwrap(), creds);
                }

                access_key = None;
                secret_key = None;
                token = None;

                let caps = profile_regex.captures(&line).unwrap();
                profile_name = Some(caps.get(1).unwrap().as_str().to_string());
                continue;
            }

            // otherwise look for key=value pairs we care about
            let lower_case_line = line.to_ascii_lowercase().to_string();

            if lower_case_line.contains("aws_access_key_id") && access_key.is_none() {
                let v: Vec<&str> = line.split('=').collect();
                if !v.is_empty() {
                    access_key = Some(v[1].trim_matches(' ').to_string());
                }
            } else if lower_case_line.contains("aws_secret_access_key") && secret_key.is_none() {
                let v: Vec<&str> = line.split('=').collect();
                if !v.is_empty() {
                    secret_key = Some(v[1].trim_matches(' ').to_string());
                }
            } else if lower_case_line.contains("aws_session_token") && token.is_none() {
                let v: Vec<&str> = line.split('=').collect();
                if !v.is_empty() {
                    token = Some(v[1].trim_matches(' ').to_string());
                }
            } else if lower_case_line.contains("aws_security_token") {
                if token.is_none() {
                    let v: Vec<&str> = line.split('=').collect();
                    if !v.is_empty() {
                        token = Some(v[1].trim_matches(' ').to_string());
                    }
                }
            } else {
                // Ignore unrecognized fields
                continue;
            }
        }

        if profile_name.is_some() && access_key.is_some() && secret_key.is_some() {
            let creds = AwsCredentials::new(access_key.unwrap(), secret_key.unwrap(), token, None);
            profiles.insert(profile_name.unwrap(), creds);
        }

        if profiles.is_empty() {
            return Err(CredentialsError::new("No credentials found."));
        }

        Ok(CredentialProfiles(profiles))
    }
}

impl fmt::Display for CredentialProfiles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (key, value) in self.0.iter() {
            writeln!(f, "[{}]", key)?;
            writeln!(f, "aws_access_key_id={}", value.aws_access_key_id())?;
            writeln!(f, "aws_secret_access_key={}", value.aws_secret_access_key())?;
            if let Some(token) = value.token() {
                writeln!(f, "aws_session_token={}", token)?;
            }
            writeln!(f, "")?;
        }

        Ok(())
    }
}

impl CredentialProfiles {
    fn set_profile<S, C>(&mut self, name: S, credentials: C) -> Result<(), Error> where S: Into<String>, C: Into<AwsCredentials> {
        match self.0.entry(name.into()) {
            Entry::Occupied(mut entry) => {
                if entry.get().token().is_some() {
                    entry.insert(credentials.into());
                } else {
                    bail!(
                        "Profile '{}' does not contain STS credentials. Ignoring",
                        entry.key()
                    );
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(credentials.into());
            }
        }
        Ok(())
    }

    fn set_profile_sts<S, C>(&mut self, name: S, credentials: C) -> Result<(), Error> where S: Into<String>, C: Into<StsCredentials> {
        let credentials = credentials.into();

        let expiry = chrono::DateTime::parse_from_rfc3339(&credentials.expiration)?;
        let expiry_utc = chrono::DateTime::from_utc(expiry.naive_utc(), chrono::offset::Utc);

        let aws_credentials = AwsCredentials::new(
            credentials.access_key_id,
            credentials.secret_access_key,
            Some(credentials.session_token),
            Some(expiry_utc)
        );
        self.set_profile(name, aws_credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate tempfile;

    use self::tempfile::Builder;
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn parse_sts() {
        let profiles: CredentialProfiles = "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN"
            .parse()
            .unwrap();

        assert_eq!(profiles.0["example"].aws_access_key_id(), "ACCESS_KEY");
        assert_eq!(
            profiles.0["example"].aws_secret_access_key(),
            "SECRET_ACCESS_KEY"
        );
        assert_eq!(
            *profiles.0["example"].token(),
            Some(String::from("SESSION_TOKEN"))
        );
    }

    #[test]
    fn parse_iam() {
        let profiles: CredentialProfiles = "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY"
            .parse()
            .unwrap();

        assert_eq!(profiles.0["example"].aws_access_key_id(), "ACCESS_KEY");
        assert_eq!(
            profiles.0["example"].aws_secret_access_key(),
            "SECRET_ACCESS_KEY"
        );
        assert_eq!(*profiles.0["example"].token(), None);
    }

    #[test]
    fn display_profiles() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            String::from("example1"),
            AwsCredentials::new("EXAMPLE1_ACCESS_KEY", "EXAMPLE1_SECRET_ACCESS_KEY", Some(String::from("EXAMPLE1_SESSION_TOKEN")), None)
        );
        profiles.insert(
            String::from("example2"),
            AwsCredentials::new("EXAMPLE2_ACCESS_KEY", "EXAMPLE2_SECRET_ACCESS_KEY", None, None)
        );

        let credential_profiles = CredentialProfiles(profiles);

        assert_eq!(format!("{}", credential_profiles), "[example1]\naws_access_key_id=EXAMPLE1_ACCESS_KEY\naws_secret_access_key=EXAMPLE1_SECRET_ACCESS_KEY\naws_session_token=EXAMPLE1_SESSION_TOKEN\n\n[example2]\naws_access_key_id=EXAMPLE2_ACCESS_KEY\naws_secret_access_key=EXAMPLE2_SECRET_ACCESS_KEY\n\n");
    }

    #[test]
    fn save_sts() {
        let mut named_tempfile = Builder::new()
            .prefix("credentials")
            .rand_bytes(5)
            .tempfile()
            .unwrap();

        write!(
            named_tempfile,
            "
[existing]
aws_access_key_id=EXISTING_ACCESS_KEY
aws_secret_access_key=EXISTING_SECRET_ACCESS_KEY
[edited]
aws_access_key_id=OLD_ACCESS_KEY
aws_secret_access_key=OLD_SECRET_ACCESS_KEY
aws_session_token=OLD_SESSION_TOKEN"
        )
        .unwrap();

        let temp_path = named_tempfile.path();

        let mut credentials_file: CredentialsFile = PathBuf::from(temp_path).try_into().unwrap();

        credentials_file.credentials.set_profile("edited", AwsCredentials::new(
            "NEW_ACCESS_KEY",
            "NEW_SECRET_ACCESS_KEY",
            Some(String::from("NEW_SESSION_TOKEN")),
            None,
        ));

        credentials_file.credentials.set_profile("new", AwsCredentials::new(
            "NEW_ACCESS_KEY",
            "NEW_SECRET_ACCESS_KEY",
            Some(String::from("NEW_SESSION_TOKEN")),
            None,
        ));

        credentials_file.save().unwrap();

        let mut buf = String::new();
        File::open(temp_path)
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();

        assert_eq!(
            &buf,
            "[edited]
aws_access_key_id=NEW_ACCESS_KEY
aws_secret_access_key=NEW_SECRET_ACCESS_KEY
aws_session_token=NEW_SESSION_TOKEN

[existing]
aws_access_key_id=EXISTING_ACCESS_KEY
aws_secret_access_key=EXISTING_SECRET_ACCESS_KEY

[new]
aws_access_key_id=NEW_ACCESS_KEY
aws_secret_access_key=NEW_SECRET_ACCESS_KEY
aws_session_token=NEW_SESSION_TOKEN

"
        );
    }

    /*#[test]
        fn double_entries() {
            let mut tmpfile: File = tempfile::tempfile().unwrap();
            write!(
                tmpfile,
                "
    [example]
    aws_access_key_id=ACCESS_KEY
    aws_secret_access_key=SECRET_ACCESS_KEY
    aws_session_token=SESSION_TOKEN
    [example]
    aws_access_key_id=ACCESS_KEY
    aws_secret_access_key=SECRET_ACCESS_KEY
    aws_session_token=SESSION_TOKEN"
            )
            .unwrap();
            tmpfile.seek(SeekFrom::Start(0)).unwrap();

            let credentials_store: CredentialsStore = tmpfile.try_into().unwrap();

            let mut expected_credentials = BTreeMap::new();
            expected_credentials.insert(
                String::from("example"),
                ProfileCredentials::Sts {
                    access_key_id: String::from("ACCESS_KEY"),
                    secret_access_key: String::from("SECRET_ACCESS_KEY"),
                    session_token: String::from("SESSION_TOKEN"),
                },
            );

            assert_eq!(credentials_store.credentials, expected_credentials);
        }

        */

}
