use crate::{aws::role::Role, okta::client::Client as OktaClient};

use failure::{err_msg, Error};
use rusoto_sts::Credentials;
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

    pub async fn into_credentials(self, client: &OktaClient) -> Result<Credentials, Error> {
        let app_link = client
            .app_links(None)
            .await?
            .into_iter()
            .find(|app_link| {
                app_link.app_name == "amazon_aws" && app_link.label == self.application_name
            })
            .ok_or_else(|| {
                format_err!("Could not find Okta application for profile {}", self.name)
            })?;

        debug!("Application Link: {:?}", &app_link);

        let saml = client
            .get_saml_response(app_link.link_url)
            .await
            .map_err(|e| {
                format_err!(
                    "Error getting SAML response for profile {} ({})",
                    self.name,
                    e
                )
            })?;

        let roles = saml.roles;

        debug!("SAML Roles: {:?}", &roles);

        let role: Role = roles
            .into_iter()
            .find(|r| r.role_name().map(|r| r == self.role).unwrap_or(false))
            .ok_or_else(|| {
                format_err!(
                    "No matching role ({}) found for profile {}",
                    self.role,
                    &self.name
                )
            })?;

        trace!("Found role: {} for profile {}", role.role_arn, &self.name);

        let assumption_response =
            crate::aws::role::assume_role(role, saml.raw, self.duration_seconds)
                .await
                .map_err(|e| {
                    format_err!("Error assuming role for profile {} ({})", self.name, e)
                })?;

        let credentials = assumption_response
            .credentials
            .ok_or_else(|| format_err!("Error fetching credentials from assumed AWS role"))?;

        trace!("Credentials: {:?}", credentials);

        Ok(credentials)
    }
}
