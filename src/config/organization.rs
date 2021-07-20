use crate::config::profile::{Profile, ProfileConfig};
use crate::multi_select;
use crate::okta::client::Client as OktaClient;

use std::convert::TryFrom;
use std::fmt::Display;
use std::fs::read_to_string;
use std::path::Path;

use anyhow::{anyhow, Error, Result};
use dialoguer::Input;
use futures::future::join_all;
use glob::Pattern;
use indexmap::IndexMap;
use rusoto_sts::Credentials;
use serde::{Deserialize, Serialize};
use toml;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrganizationConfig {
    pub role: Option<String>,
    pub username: Option<String>,
    pub duration_seconds: Option<i64>,
    pub profiles: IndexMap<String, ProfileConfig>,
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

        // let selected_links =
        //     multi_select(aws_links.collect(), "Choose Okta Applications", |link| {
        //         link.label.clone()
        //     })?;

        let profile_futures = aws_links
            .into_iter()
            .map(|link| ProfileConfig::from_app_link(client, link));

        Ok(OrganizationConfig {
            username: Some(username),
            duration_seconds: None,
            role: None,
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

        let username = match cfg.clone().username {
            Some(username) => username,
            None => prompt_username(&filename)?,
        };

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
            username,
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

    pub async fn into_credentials(
        self,
        client: &OktaClient,
        filter: Pattern,
    ) -> impl Iterator<Item = (String, Credentials)> {
        let org_name = self.name.clone();

        let futures = self.into_profiles(filter).map(|profile| async {
            let name = profile.name.clone();

            info!("Requesting tokens for {}/{}", org_name, profile.name);

            let credentials = profile.into_credentials(&client).await.unwrap();

            (name, credentials)
        });

        join_all(futures).await.into_iter()
    }
}

pub fn prompt_username(organization: &impl Display) -> Result<String, Error> {
    let mut input = Input::<String>::new();
    input.with_prompt(&format!("Username for {}", organization));

    if let Ok(system_user) = username::get_user_name() {
        input.default(system_user);
    }

    input.interact_text().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Write;

    use tempfile;

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

        assert_eq!(organization.profiles[0].name, "foo");
        assert_eq!(organization.profiles[0].application_name, "foo");
        assert_eq!(organization.profiles[0].role, "my_role");
        assert_eq!(organization.profiles[0].duration_seconds, Some(300));

        assert_eq!(organization.profiles[1].name, "bar");
        assert_eq!(organization.profiles[1].application_name, "bar");
        assert_eq!(organization.profiles[1].role, "my_role");
        assert_eq!(organization.profiles[1].duration_seconds, Some(600));

        assert_eq!(organization.profiles[2].name, "baz");
        assert_eq!(organization.profiles[2].application_name, "baz");
        assert_eq!(organization.profiles[2].role, "baz_role");
        assert_eq!(organization.profiles[2].duration_seconds, Some(300));
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
}
