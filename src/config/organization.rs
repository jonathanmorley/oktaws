use crate::config::profile::{Profile, ProfileConfig};
use crate::{aws::role::Role, okta::client::Client as OktaClient};

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Display;
use std::path::Path;

use confy;
use dialoguer::Input;
use failure::Error;
use futures::future::join_all;
use glob::Pattern;
use rusoto_sts::Credentials;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrganizationConfig {
    pub role: Option<String>,
    pub username: Option<String>,
    pub duration_seconds: Option<i64>,
    pub profiles: HashMap<String, ProfileConfig>,
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
        let cfg: OrganizationConfig = confy::load_path(path)?;

        let filename = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .ok_or_else(|| format_err!("Organization name not parseable from {:?}", path))?;

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
    pub fn profiles(&self, filter: Pattern) -> impl Iterator<Item = &Profile> {
        self.profiles
            .iter()
            .filter(move |&p| filter.matches(&p.name))
    }

    pub fn into_profiles(self, filter: Pattern) -> impl Iterator<Item = Profile> {
        self.profiles
            .into_iter()
            .filter(move |p| filter.matches(&p.name))
    }

    pub async fn into_credentials(self, client: &OktaClient, filter: Pattern) -> HashMap<String, Credentials> {
        let org_name = self.name.clone();
        
        let futures = self
            .into_profiles(filter)
            .map(|profile| {
                async {
                    let name = profile.name.clone();

                    info!(
                        "Requesting tokens for {}/{}",
                        org_name, profile.name
                    );

                    let credentials = profile.into_credentials(&client).await.unwrap();

                    (name, credentials)
                }
            });

        join_all(futures).await.into_iter().collect()
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
