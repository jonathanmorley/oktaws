use crate::config::oktaws_home;
use crate::config::profile::{Profile, ProfileConfig};
use crate::okta::client::Client as OktaClient;
use crate::select_opt;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::read_to_string;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Error, Result};
use aws_types::Credentials;
use derive_more::Display;
use futures::future::join_all;
use glob::{glob, Pattern};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use toml;
use tracing::{debug, error, instrument};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrganizationConfig {
    pub username: String,
    pub role: Option<String>,
    pub duration_seconds: Option<i32>,
    #[serde(serialize_with = "toml::ser::tables_last")]
    pub profiles: HashMap<String, ProfileConfig>,
}

impl OrganizationConfig {
    pub async fn from_organization(
        client: &OktaClient,
        username: String,
    ) -> Result<OrganizationConfig> {
        let app_links = client.app_links(None).await?;
        let aws_links = app_links
            .into_iter()
            .filter(|link| link.app_name == "amazon_aws");
        let selected_links = aws_links.collect::<Vec<_>>();

        let roles = client.all_roles(&selected_links).await?;

        let mut role_names = roles
            .into_iter()
            .map(|r| r.role_name())
            .collect::<Result<Vec<_>>>()?;
        role_names.sort();

        // This is to try to remove any single-items from the list, then dedup
        let default_role_names = role_names
            .into_iter()
            .dedup_with_count()
            .filter(|&(i, _)| i > 1)
            .map(|(_, x)| x)
            .collect::<Vec<_>>();
        let default_role = select_opt(
            default_role_names,
            "Choose Default Role [None]",
            ToOwned::to_owned,
        )?;

        let profile_futures = selected_links
            .into_iter()
            .map(|link| ProfileConfig::from_app_link(client, link, default_role.clone()));

        Ok(OrganizationConfig {
            username,
            duration_seconds: None,
            role: default_role.clone(),
            profiles: join_all(profile_futures)
                .await
                .into_iter()
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Organization {
    pub name: String,
    pub username: String,
    pub profiles: Vec<Profile>,
}

impl TryFrom<&Path> for Organization {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let cfg: OrganizationConfig = toml::de::from_str(&read_to_string(path)?)?;

        let filename = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .ok_or_else(|| anyhow!("Organization name not parseable from {:?}", path))?;

        let profiles = cfg
            .profiles
            .iter()
            .map(|(name, profile_config)| {
                Profile::try_from_config(
                    profile_config,
                    name.to_string(),
                    cfg.role.clone(),
                    cfg.duration_seconds,
                )
            })
            .collect::<Result<Vec<Profile>, Error>>()?;

        Ok(Organization {
            name: filename,
            username: cfg.username,
            profiles,
        })
    }
}

impl Organization {
    pub fn into_profiles(self, filter: Pattern) -> impl Iterator<Item = Profile> {
        self.profiles
            .into_iter()
            .filter(move |p| filter.matches(&p.name))
    }

    #[instrument(skip_all, fields(organization=%self.name, profiles=%filter))]
    pub async fn into_credentials(
        self,
        client: &OktaClient,
        filter: Pattern,
    ) -> impl Iterator<Item = (String, Credentials)> {
        let futures = self.into_profiles(filter).map(|profile| async {
            (profile.name.clone(), profile.into_credentials(client).await)
        });

        join_all(futures)
            .await
            .into_iter()
            .filter_map(|cred_result| match cred_result {
                (profile, Ok(creds)) => Some((profile, creds)),
                (_, Err(e)) => {
                    error!("{e}");
                    None
                }
            })
    }
}

#[derive(Debug, Display)]
pub struct OrganizationPattern(Pattern);

impl FromStr for OrganizationPattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let path_pattern = oktaws_home()?.join(format!("{s}.toml"));
        let pattern = path_pattern.as_os_str().to_string_lossy();

        Ok(OrganizationPattern(Pattern::new(&pattern)?))
    }
}

impl OrganizationPattern {
    pub fn organizations(&self) -> Result<Vec<Organization>> {
        let paths = glob(self.0.as_str())?
            .map(|r| r.map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;

        debug!("Found organization paths: {paths:?}");

        paths.iter().map(|p| p.as_path().try_into()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::File;
    use std::io::Write;

    use serial_test::serial;
    use tempfile::{self, TempDir};

    fn create_mock_toml(dir: &Path, name: &str) {
        let filepath = dir.join(format!("{}.toml", name));
        let mut file = File::create(filepath).unwrap();
        write!(file, "username = \"{}_user\"\n[profiles]", name).unwrap();
    }

    fn create_mock_config_dir() -> TempDir {
        let tempdir = tempfile::tempdir().unwrap();

        for organization_name in ["foo", "bar", "baz"] {
            create_mock_toml(tempdir.path(), organization_name);
        }

        let bad_filepath = tempdir.path().join("bad.txt");
        let mut bad_file = File::create(bad_filepath).unwrap();
        write!(bad_file, "Not an oktaws config").unwrap();

        let bad_dir = tempdir.path().join("bad");
        std::fs::create_dir(&bad_dir).unwrap();
        let bad_nested_filepath = bad_dir.join("nested.txt");
        let mut bad_nested_file = File::create(bad_nested_filepath).unwrap();
        write!(bad_nested_file, "Not an oktaws config").unwrap();

        tempdir
    }

    #[test]
    fn parse_organization() {
        let tempdir = tempfile::tempdir().unwrap();

        let filepath = tempdir.path().join("mock_org.toml");
        let mut file = File::create(filepath.clone()).unwrap();

        write!(
            file,
            r#"
username = "mock_user"
duration_seconds = 300
role = "my_role"
[profiles]
foo = "foo"
bar = {{ application = "bar", duration_seconds = 600 }}
baz = {{ application = "baz", role = "baz_role" }}
"#
        )
        .unwrap();

        let organization = Organization::try_from(filepath.as_path()).unwrap();

        assert_eq!(organization.name, "mock_org");
        assert_eq!(organization.username, "mock_user");
        assert_eq!(organization.profiles.len(), 3);

        assert!(organization.profiles.contains(&Profile {
            name: String::from("foo"),
            application_name: String::from("foo"),
            role: String::from("my_role"),
            duration_seconds: Some(300)
        }));

        assert!(organization.profiles.contains(&Profile {
            name: String::from("bar"),
            application_name: String::from("bar"),
            role: String::from("my_role"),
            duration_seconds: Some(600)
        }));

        assert!(organization.profiles.contains(&Profile {
            name: String::from("baz"),
            application_name: String::from("baz"),
            role: String::from("baz_role"),
            duration_seconds: Some(300)
        }));
    }

    #[test]
    fn must_have_profiles() {
        let tempdir = tempfile::tempdir().unwrap();

        let filepath = tempdir.path().join("mock_org.toml");
        let mut file = File::create(filepath.clone()).unwrap();

        write!(
            file,
            r#"
username = "mock_user"
"#
        )
        .unwrap();

        let err = Organization::try_from(filepath.as_path()).unwrap_err();

        assert_eq!(
            err.to_string(),
            "missing field `profiles` at line 1 column 1"
        );
    }

    #[test]
    fn profile_must_have_role() {
        let tempdir = tempfile::tempdir().unwrap();

        let filepath = tempdir.path().join("mock_org.toml");
        let mut file = File::create(filepath.clone()).unwrap();

        write!(
            file,
            r#"
username = "mock_user"
[profiles]
foo = "foo"
"#
        )
        .unwrap();

        let err = Organization::try_from(filepath.as_path()).unwrap_err();

        assert_eq!(err.to_string(), "No role found");
    }

    #[test]
    fn profile_without_duration() {
        let tempdir = tempfile::tempdir().unwrap();

        let filepath = tempdir.path().join("mock_org.toml");
        let mut file = File::create(filepath.clone()).unwrap();

        write!(
            file,
            r#"
username = "mock_user"
role = "my_role"
[profiles]
foo = "foo"
"#
        )
        .unwrap();

        let organization = Organization::try_from(filepath.as_path()).unwrap();

        assert_eq!(organization.profiles.len(), 1);

        assert_eq!(organization.profiles[0].name, "foo");
        assert_eq!(organization.profiles[0].application_name, "foo");
        assert_eq!(organization.profiles[0].role, "my_role");
        assert_eq!(organization.profiles[0].duration_seconds, None);
    }

    #[test]
    #[serial]
    fn finds_all_organizations() {
        let tempdir = create_mock_config_dir();
        env::set_var("OKTAWS_HOME", tempdir.path());

        let org_pattern: OrganizationPattern = "*".parse().unwrap();
        let organizations = org_pattern.organizations().unwrap();

        assert_eq!(organizations.len(), 3);
    }

    #[test]
    #[serial]
    fn does_not_find_nested_config() {
        let tempdir = create_mock_config_dir();

        env::set_var("OKTAWS_HOME", &tempdir.path());

        let mock_dir = tempdir.path().join("mock");
        std::fs::create_dir(&mock_dir).unwrap();
        create_mock_toml(&mock_dir, "quz");

        let org_pattern: OrganizationPattern = "*".parse().unwrap();
        let organizations = org_pattern.organizations().unwrap();

        assert_eq!(organizations.len(), 3);
    }

    #[test]
    #[serial]
    fn filters_into_organizations() {
        let tempdir = create_mock_config_dir();
        env::set_var("OKTAWS_HOME", tempdir.path());

        let org_pattern: OrganizationPattern = "ba*".parse().unwrap();
        let organizations = org_pattern.organizations().unwrap();

        assert_eq!(organizations.len(), 2);
    }
}
