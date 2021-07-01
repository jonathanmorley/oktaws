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
    pub fn try_from_config(
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
