use std::convert::{TryFrom, TryInto};
use std::env::var as env_var;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::path::PathBuf;
use std::str;

use anyhow::{anyhow, Error, Result};
use dirs;
use indexmap::map::Entry;
use indexmap::IndexMap;
use path_abs::PathFile;
use rusoto_sts::Credentials;
use serde::{Deserialize, Serialize};

// `IndexMaps`s are sorted based on insert order
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Profile(IndexMap<String, String>);

impl Profile {
    fn is_sts_credentials(&self) -> bool {
        self.0.contains_key("aws_access_key_id")
            && self.0.contains_key("aws_secret_access_key")
            && self.0.contains_key("aws_session_token")
    }

    fn set_sts_credentials(&mut self, creds: StsCreds) -> Result<()> {
        if !self.is_sts_credentials() {
            return Err(anyhow!("Profile is not STS. Cannot set STS credentials"));
        }

        for (key, value) in Profile::from(creds).0 {
            self.0.insert(key, value);
        }

        Ok(())
    }
}

impl From<StsCreds> for Profile {
    fn from(creds: StsCreds) -> Self {
        let mut map = IndexMap::default();

        map.insert("aws_access_key_id".to_string(), creds.aws_access_key_id);
        map.insert(
            "aws_secret_access_key".to_string(),
            creds.aws_secret_access_key,
        );
        map.insert("aws_session_token".to_string(), creds.aws_session_token);

        Profile(map)
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct StsCreds {
    aws_access_key_id: String,
    aws_secret_access_key: String,
    aws_session_token: String,
}

impl TryFrom<Profile> for StsCreds {
    type Error = Error;

    fn try_from(mut profile: Profile) -> Result<Self, Self::Error> {
        Ok(StsCreds {
            aws_access_key_id: profile
                .0
                .remove("aws_access_key_id")
                .ok_or_else(|| anyhow!("No aws_access_key_id found"))?,
            aws_secret_access_key: profile
                .0
                .remove("aws_secret_access_key")
                .ok_or_else(|| anyhow!("No aws_secret_access_key found"))?,
            aws_session_token: profile
                .0
                .remove("aws_session_token")
                .ok_or_else(|| anyhow!("No aws_secret_access_key found"))?,
        })
    }
}

impl From<rusoto_sts::Credentials> for StsCreds {
    fn from(creds: rusoto_sts::Credentials) -> Self {
        StsCreds {
            aws_access_key_id: creds.access_key_id,
            aws_secret_access_key: creds.secret_access_key,
            aws_session_token: creds.session_token,
        }
    }
}

#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Profiles(IndexMap<String, Profile>);

impl Profiles {
    pub fn set_sts_credentials(&mut self, name: String, creds: StsCreds) -> Result<(), Error> {
        match self.0.entry(name) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().set_sts_credentials(creds)?;
            }
            Entry::Vacant(entry) => {
                entry.insert(creds.into());
            }
        }
        Ok(())
    }

    fn read_as_ini<R>(reader: R) -> Result<Self, Error>
    where
        R: Read,
    {
        serde_ini::de::from_read(reader).map_err(Into::into)
    }

    fn write_as_ini<W>(&self, writer: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        serde_ini::to_writer(writer, self).map_err(Into::into)
    }
}

#[derive(Debug)]
pub struct CredentialsStore {
    file: File,
    pub profiles: Profiles,
}

impl CredentialsStore {
    pub fn new() -> Result<CredentialsStore, Error> {
        match env_var("AWS_SHARED_CREDENTIALS_FILE") {
            Ok(path) => PathBuf::from(path),
            Err(_) => CredentialsStore::default_profile_location()?,
        }
        .try_into()
    }

    pub fn save(&mut self) -> Result<(), Error> {
        info!("Saving AWS credentials");
        self.profiles.write_as_ini(&mut self.file)
    }

    fn default_profile_location() -> Result<PathBuf, Error> {
        match dirs::home_dir() {
            Some(home_dir) => Ok(home_dir.join(".aws").join("credentials")),
            None => Err(anyhow!("The environment variable HOME must be set.")),
        }
    }
}

impl TryFrom<PathBuf> for CredentialsStore {
    type Error = Error;

    fn try_from(file_path: PathBuf) -> Result<Self, Self::Error> {
        file_path.as_path().try_into()
    }
}

impl TryFrom<&Path> for CredentialsStore {
    type Error = Error;

    fn try_from(file_path: &Path) -> Result<Self, Self::Error> {
        PathFile::create(&file_path)?.try_into()
    }
}

impl TryFrom<PathFile> for CredentialsStore {
    type Error = Error;

    fn try_from(file_path: PathFile) -> Result<Self, Self::Error> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_path)?
            .try_into()
    }
}

impl TryFrom<File> for CredentialsStore {
    type Error = Error;

    fn try_from(mut file: File) -> Result<Self, Self::Error> {
        let profiles = Profiles::read_as_ini(&file)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(CredentialsStore { file, profiles })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum ProfileCredentials {
    Sts {
        #[serde(rename = "aws_access_key_id")]
        access_key_id: String,
        #[serde(rename = "aws_secret_access_key")]
        secret_access_key: String,
        #[serde(rename = "aws_session_token")]
        session_token: String,
    },
    Iam {
        #[serde(rename = "aws_access_key_id")]
        access_key_id: String,
        #[serde(rename = "aws_secret_access_key")]
        secret_access_key: String,
    },
}

impl From<Credentials> for ProfileCredentials {
    fn from(creds: Credentials) -> Self {
        ProfileCredentials::Sts {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::{Read, Write};

    use tempfile;
    use tempfile::Builder;

    #[test]
    fn parse_profiles_with_extra_fields() {
        let profiles_ini = "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN
foo=bar";

        let profiles = Profiles::read_as_ini(profiles_ini.as_bytes()).unwrap();

        assert_eq!(profiles.0["example"].0["aws_access_key_id"], "ACCESS_KEY");
        assert_eq!(
            profiles.0["example"].0["aws_secret_access_key"],
            "SECRET_ACCESS_KEY"
        );
        assert_eq!(
            profiles.0["example"].0["aws_session_token"],
            "SESSION_TOKEN"
        );
        assert_eq!(profiles.0["example"].0["foo"], "bar");
    }

    #[test]
    fn write_profiles_with_extra_fields() {
        let creds = StsCreds {
            aws_access_key_id: "ACCESS_KEY".to_string(),
            aws_secret_access_key: "SECRET_ACCESS_KEY".to_string(),
            aws_session_token: "SESSION_TOKEN".to_string(),
        };

        let mut profile: Profile = creds.into();
        profile.0.insert("foo".to_string(), "bar".to_string());

        let mut map = IndexMap::default();
        map.insert("example".to_string(), profile);
        let profiles = Profiles(map);

        let mut w = Vec::new();
        profiles.write_as_ini(&mut w).unwrap();

        assert_eq!(
            &String::from_utf8(w).unwrap(),
            "[example]\r
aws_access_key_id=ACCESS_KEY\r
aws_secret_access_key=SECRET_ACCESS_KEY\r
aws_session_token=SESSION_TOKEN\r
foo=bar\r
"
        );
    }

    #[test]
    fn parse_double_profiles() {
        let profiles_ini = "
[example]
aws_access_key_id=ACCESS_KEY_1
aws_secret_access_key=SECRET_ACCESS_KEY_1
aws_session_token=SESSION_TOKEN_1
[example]
aws_access_key_id=ACCESS_KEY_2
aws_secret_access_key=SECRET_ACCESS_KEY_2
aws_session_token=SESSION_TOKEN_2";

        let profiles = Profiles::read_as_ini(profiles_ini.as_bytes()).unwrap();

        assert_eq!(profiles.0.len(), 1);
        assert_eq!(profiles.0["example"].0["aws_access_key_id"], "ACCESS_KEY_2");
        assert_eq!(
            profiles.0["example"].0["aws_secret_access_key"],
            "SECRET_ACCESS_KEY_2"
        );
        assert_eq!(
            profiles.0["example"].0["aws_session_token"],
            "SESSION_TOKEN_2"
        );
    }

    #[test]
    fn update_sts_credentials() {
        let profiles_ini = "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN
foo=bar";

        let mut profiles = Profiles::read_as_ini(profiles_ini.as_bytes()).unwrap();

        profiles
            .set_sts_credentials(
                "example".to_string(),
                StsCreds {
                    aws_access_key_id: "NEW_ACCESS_KEY".to_string(),
                    aws_secret_access_key: "NEW_SECRET_ACCESS_KEY".to_string(),
                    aws_session_token: "NEW_SESSION_TOKEN".to_string(),
                },
            )
            .unwrap();

        assert_eq!(
            profiles.0["example"].0["aws_access_key_id"],
            "NEW_ACCESS_KEY"
        );
        assert_eq!(
            profiles.0["example"].0["aws_secret_access_key"],
            "NEW_SECRET_ACCESS_KEY"
        );
        assert_eq!(
            profiles.0["example"].0["aws_session_token"],
            "NEW_SESSION_TOKEN"
        );
    }

    #[test]
    fn add_sts_credentials() {
        let mut profiles = Profiles::default();

        profiles
            .set_sts_credentials(
                "example".to_string(),
                StsCreds {
                    aws_access_key_id: "NEW_ACCESS_KEY".to_string(),
                    aws_secret_access_key: "NEW_SECRET_ACCESS_KEY".to_string(),
                    aws_session_token: "NEW_SESSION_TOKEN".to_string(),
                },
            )
            .unwrap();

        assert_eq!(
            profiles.0["example"].0["aws_access_key_id"],
            "NEW_ACCESS_KEY"
        );
        assert_eq!(
            profiles.0["example"].0["aws_secret_access_key"],
            "NEW_SECRET_ACCESS_KEY"
        );
        assert_eq!(
            profiles.0["example"].0["aws_session_token"],
            "NEW_SESSION_TOKEN"
        );
    }

    #[test]
    fn cannot_set_sts_creds_on_non_sts_profile() {
        let profiles_ini = "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
foo=bar";

        let mut profiles = Profiles::read_as_ini(profiles_ini.as_bytes()).unwrap();

        let profile = profiles.0.get_mut("example").unwrap();

        let err = profile
            .set_sts_credentials(StsCreds {
                aws_access_key_id: "NEW_ACCESS_KEY".to_string(),
                aws_secret_access_key: "NEW_SECRET_ACCESS_KEY".to_string(),
                aws_session_token: "NEW_SESSION_TOKEN".to_string(),
            })
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "Profile is not STS. Cannot set STS credentials"
        );
    }

    #[test]
    fn cannot_parse_bad_ini() {
        let profiles_ini = "[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
foo";

        let err = Profiles::read_as_ini(profiles_ini.as_bytes()).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Custom(\"INI syntax error: variable assignment missing '='\")"
        );
    }

    #[test]
    fn roundtrip_with_update() {
        // This also checks that non-alphabetical ordering is preserved.
        // Comments are not currnetly preserved
        let profiles_ini = "[example_sts]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN
# This is important
bar=baz

[example_static]
aws_secret_access_key=SECRET_ACCESS_KEY
aws_access_key_id=ACCESS_KEY
foo=bar
";

        let mut profiles = Profiles::read_as_ini(profiles_ini.as_bytes()).unwrap();

        let profile = profiles.0.get_mut("example_sts").unwrap();

        profile
            .set_sts_credentials(StsCreds {
                aws_access_key_id: "NEW_ACCESS_KEY".to_string(),
                aws_secret_access_key: "NEW_SECRET_ACCESS_KEY".to_string(),
                aws_session_token: "NEW_SESSION_TOKEN".to_string(),
            })
            .unwrap();

        let mut w = Vec::new();
        profiles.write_as_ini(&mut w).unwrap();

        assert_eq!(
            String::from_utf8(w).unwrap(),
            "[example_sts]\r
aws_access_key_id=NEW_ACCESS_KEY\r
aws_secret_access_key=NEW_SECRET_ACCESS_KEY\r
aws_session_token=NEW_SESSION_TOKEN\r
bar=baz\r
[example_static]\r
aws_secret_access_key=SECRET_ACCESS_KEY\r
aws_access_key_id=ACCESS_KEY\r
foo=bar\r
"
        );
    }

    #[test]
    fn write_to_file() {
        let mut named_tempfile = Builder::new()
            .prefix("credentials")
            .rand_bytes(5)
            .tempfile()
            .unwrap();

        write!(
            named_tempfile,
            "
[existing]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY

[example]
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET_ACCESS_KEY
aws_session_token=SESSION_TOKEN"
        )
        .unwrap();

        let temp_path = named_tempfile.path();

        let mut credentials_store: CredentialsStore = temp_path.try_into().unwrap();

        credentials_store
            .profiles
            .set_sts_credentials(
                String::from("example"),
                StsCreds {
                    aws_access_key_id: String::from("ACCESS_KEY2"),
                    aws_secret_access_key: String::from("SECRET_ACCESS_KEY2"),
                    aws_session_token: String::from("SESSION_TOKEN2"),
                },
            )
            .unwrap();

        credentials_store.save().unwrap();

        let mut buf = String::new();
        File::open(temp_path)
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();

        assert_eq!(
            &buf,
            "[existing]\r
aws_access_key_id=ACCESS_KEY\r
aws_secret_access_key=SECRET_ACCESS_KEY\r
[example]\r
aws_access_key_id=ACCESS_KEY2\r
aws_secret_access_key=SECRET_ACCESS_KEY2\r
aws_session_token=SESSION_TOKEN2\r
"
        );
    }
}
