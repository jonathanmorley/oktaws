use mockall_double::double;

use crate::config::oktaws_home;
use crate::config::profile::{self, Profile};
#[double]
use crate::okta::client::Client as OktaClient;
use crate::select_opt;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::read_to_string;
use std::path::Path;
use std::str::FromStr;
use std::{fmt, io};

use aws_credential_types::Credentials;
use dialoguer::Input;
use eyre::{eyre, Error, Result};
use futures::future::join_all;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use toml;
use tracing::{debug, error, instrument};

/// This is an intentionally 'loose' struct,
/// representing the potential for overrides and later prompts
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub username: Option<String>,
    pub role: Option<String>,
    pub duration_seconds: Option<i32>,
    pub profiles: HashMap<String, profile::Config>,
}

impl Config {
    /// Create a config object from an Okta organization
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors fetching the information
    /// from Okta to form the config,
    /// or if there are errors during prompting of a default role.
    pub async fn from_organization(client: &OktaClient, username: String) -> Result<Self> {
        let app_links = client.app_links(None).await?;
        let aws_links = app_links
            .into_iter()
            .filter(|link| link.app_name == "amazon_aws");
        let selected_links = aws_links.collect::<Vec<_>>();

        let roles = client.all_roles(selected_links.clone()).await?;

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

        let default_role = if default_role_names.is_empty() {
            None
        } else {
            select_opt(
                default_role_names,
                "Choose Default Role [None]",
                ToOwned::to_owned,
            )?
        };

        let profile_futures = selected_links
            .into_iter()
            .map(|link| profile::Config::from_app_link(client, link, default_role.clone()));

        Ok(Self {
            username: Some(username),
            duration_seconds: None,
            role: default_role.clone(),
            profiles: join_all(profile_futures)
                .await
                .into_iter()
                .collect::<Result<_, _>>()?,
        })
    }
}

/// This is a canonical representation of the Organization,
/// with Options resolved and defaults propagated.
#[derive(Clone, Debug)]
pub struct Organization {
    pub name: String,
    pub username: String,
    pub profiles: Vec<Profile>,
}

impl TryFrom<&Path> for Organization {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let cfg: Config = toml::de::from_str(&read_to_string(path)?)?;

        let filename = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .ok_or_else(|| eyre!("Organization name not parseable from {:?}", path))?;

        let username = match cfg.clone().username {
            Some(username) => username,
            None => prompt_username(&filename)?,
        };

        let profiles = cfg
            .profiles
            .iter()
            .map(|(name, profile_config)| {
                Profile::try_from_spec(
                    profile_config,
                    name.to_string(),
                    cfg.role.clone(),
                    cfg.duration_seconds,
                )
            })
            .collect::<Result<Vec<Profile>, Error>>()?;

        Ok(Self {
            name: filename,
            username,
            profiles,
        })
    }
}

/// Prompt for a username for a given Okta organization.
///
/// # Errors
///
/// Will return `Err` if there are any IO errors during the prompt
pub fn prompt_username(organization: &impl fmt::Display) -> Result<String, io::Error> {
    let mut input = Input::<String>::new();
    input.with_prompt(&format!("Username for {organization}"));

    if let Ok(system_user) = username::get_user_name() {
        input.default(system_user);
    }

    input.interact_text()
}

impl Organization {
    pub fn into_profiles(self, filter: glob::Pattern) -> impl Iterator<Item = Profile> {
        self.profiles
            .into_iter()
            .filter(move |p| filter.matches(&p.name))
    }

    #[instrument(skip_all, fields(organization=%self.name, profiles=%filter))]
    pub async fn into_credentials(
        self,
        client: &OktaClient,
        filter: glob::Pattern,
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

#[derive(Clone, Debug)]
pub struct Pattern(glob::Pattern);

impl FromStr for Pattern {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self> {
        let path_pattern = oktaws_home()?.join(format!("{s}.toml"));
        let pattern = path_pattern.as_os_str().to_string_lossy();

        Ok(Self(glob::Pattern::new(&pattern)?))
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Pattern {
    /// Find and parse all the organization configs
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors globbing the paths,
    /// or reading and parsing the config files.
    pub fn organizations(&self) -> Result<Vec<Organization>> {
        let paths = glob::glob(self.0.as_str())?
            .map(|r| r.map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;

        debug!("Found organization paths: {paths:?}");

        paths.iter().map(|p| p.as_path().try_into()).collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::aws::role::SamlRole;

    use super::*;

    use std::env;
    use std::fs::File;
    use std::io::Write;

    use serial_test::serial;
    use tempfile::{self, TempDir};

    fn create_mock_toml(dir: &Path, name: &str) {
        let filepath = dir.join(format!("{name}.toml"));
        let mut file = File::create(filepath).unwrap();
        write!(file, "username = \"{name}_user\"\n[profiles]").unwrap();
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
            account: None,
            role: String::from("my_role"),
            duration_seconds: Some(300)
        }));

        assert!(organization.profiles.contains(&Profile {
            name: String::from("bar"),
            application_name: String::from("bar"),
            account: None,
            role: String::from("my_role"),
            duration_seconds: Some(600)
        }));

        assert!(organization.profiles.contains(&Profile {
            name: String::from("baz"),
            application_name: String::from("baz"),
            account: None,
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
            "TOML parse error at line 1, column 1\n  |\n1 | \n  | ^\nmissing field `profiles`\n"
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

        let org_pattern: Pattern = "*".parse().unwrap();
        let organizations = org_pattern.organizations().unwrap();

        assert_eq!(organizations.len(), 3);
    }

    #[test]
    #[serial]
    fn does_not_find_nested_config() {
        let tempdir = create_mock_config_dir();

        env::set_var("OKTAWS_HOME", tempdir.path());

        let mock_dir = tempdir.path().join("mock");
        std::fs::create_dir(&mock_dir).unwrap();
        create_mock_toml(&mock_dir, "quz");

        let org_pattern: Pattern = "*".parse().unwrap();
        let organizations = org_pattern.organizations().unwrap();

        assert_eq!(organizations.len(), 3);
    }

    #[test]
    #[serial]
    fn filters_into_organizations() {
        let tempdir = create_mock_config_dir();
        env::set_var("OKTAWS_HOME", tempdir.path());

        let org_pattern: Pattern = "ba*".parse().unwrap();
        let organizations = org_pattern.organizations().unwrap();

        assert_eq!(organizations.len(), 2);
    }

    #[tokio::test]
    async fn init_without_obvious_default_role() {
        let mut client = OktaClient::new();
        client.expect_app_links().returning(|_| Ok(Vec::new()));
        
        // With two (different) roles
        client.expect_all_roles().returning(|_| Ok(vec![
            SamlRole {
                provider: "arn:aws:iam::123456789012:saml-provider/okta-idp"
                    .parse()
                    .unwrap(),
                role: "arn:aws:iam::123456789012:role/mock-role".parse().unwrap(),
            },
            SamlRole {
                provider: "arn:aws:iam::123456789012:saml-provider/okta-idp"
                    .parse()
                    .unwrap(),
                role: "arn:aws:iam::123456789012:role/mock-role-2".parse().unwrap(),
            }
        ]));

        let config = Config::from_organization(&client, String::from("test_user")).await.unwrap();

        assert_eq!(config.role, None);
    }
}
