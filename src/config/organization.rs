use crate::config::credentials;
use crate::okta::Organization as OktaOrganization;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;

use confy;
use failure::{err_msg, Error};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ProfileConfig {
    Name(String),
    Detailed(FullProfileConfig),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FullProfileConfig {
    pub application: String,
    pub role: Option<String>,
    pub duration_seconds: Option<i64>,
}

impl From<ProfileConfig> for FullProfileConfig {
    fn from(profile_config: ProfileConfig) -> Self {
        match profile_config {
            ProfileConfig::Detailed(config) => config,
            ProfileConfig::Name(application) => FullProfileConfig {
                application,
                role: None,
                duration_seconds: None,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Profile {
    pub name: String,
    pub application_name: String,
    pub role: String,
    pub duration_seconds: Option<i64>,
}

impl Profile {
    fn try_from_config(
        profile_config: &ProfileConfig,
        name: String,
        default_role: Option<String>,
        default_duration_seconds: Option<i64>,
    ) -> Result<Profile, Error> {
        let full_profile_config: FullProfileConfig = profile_config.to_owned().into();

        Ok(Profile {
            name,
            application_name: full_profile_config.application,
            role: full_profile_config
                .role
                .or(default_role)
                .ok_or_else(|| err_msg("No role found"))?,
            duration_seconds: full_profile_config
                .duration_seconds
                .or(default_duration_seconds),
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrganizationConfig {
    pub role: Option<String>,
    pub username: Option<String>,
    pub duration_seconds: Option<i64>,
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Clone, Debug)]
pub struct Organization {
    pub okta_organization: OktaOrganization,
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
        let okta_organization = filename.parse()?;

        let username = match cfg.clone().username {
            Some(username) => username,
            None => credentials::get_username(&okta_organization)?,
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
            okta_organization,
            username,
            profiles,
        })
    }
}
