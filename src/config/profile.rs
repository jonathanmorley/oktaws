use crate::{
    aws::{get_account_alias, role::SamlRole, sts_client},
    okta::applications::AppLink,
    okta::client::Client as OktaClient,
    saml::extract_account_name,
    select,
};

use anyhow::{anyhow, Result};
use aws_types::Credentials;
use serde::{Deserialize, Serialize};
use tracing::{instrument, trace, warn};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Spec {
    Name(String),
    Detailed(FullSpec),
}

impl Spec {
    #[instrument(skip(client, link, default_role), fields(organization=%client.base_url, application=%link.label))]
    pub async fn from_app_link(
        client: &OktaClient,
        link: AppLink,
        default_role: Option<String>,
    ) -> Result<(String, Self)> {
        let response = client.get_saml_response(link.link_url).await?;
        let aws_response = match response.post_to_aws().await {
            Err(e) => {
                warn!("Caught error trying to login to AWS: {}, trying again", e);
                response.post_to_aws().await
            }
            ok => ok,
        }?;
        let aws_response_text = aws_response.text().await?;

        let roles = response.clone().roles;

        let saml_role = match roles.len() {
            0 => Err(anyhow!("No role found")),
            1 => Ok(roles.get(0).unwrap()),
            _ => {
                if let Some(default_role) = default_role.clone() {
                    match roles
                        .iter()
                        .find(|role| role.role_name().unwrap() == default_role)
                    {
                        Some(role) => Ok(role),
                        None => select(
                            roles.iter().collect(),
                            format!("Choose Role for {}", link.label),
                            |role| role.role.clone(),
                        )
                        .map_err(Into::into),
                    }
                } else {
                    select(
                        roles.iter().collect(),
                        format!("Choose Role for {}", link.label),
                        |role| role.role.clone(),
                    )
                    .map_err(Into::into)
                }
            }
        }?;

        let role_name = saml_role.role_name()?.to_string();

        let account_name = get_account_alias(saml_role, &response)
            .await
            .or_else(|_| extract_account_name(&aws_response_text))
            .unwrap_or_else(|_| {
                warn!("No AWS account alias found. Falling back on Okta Application name");
                link.label.clone()
            });

        let profile_config = if Some(role_name.clone()) == default_role {
            Self::Name(link.label)
        } else {
            Self::Detailed(FullSpec {
                application: link.label,
                role: Some(role_name),
                duration_seconds: None,
            })
        };

        Ok((account_name, profile_config))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FullSpec {
    pub application: String,
    pub role: Option<String>,
    pub duration_seconds: Option<i32>,
}

impl From<Spec> for FullSpec {
    fn from(profile_config: Spec) -> Self {
        match profile_config {
            Spec::Detailed(config) => config,
            Spec::Name(application) => Self {
                application,
                role: None,
                duration_seconds: None,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Profile {
    pub name: String,
    pub application_name: String,
    pub role: String,
    pub duration_seconds: Option<i32>,
}

impl Profile {
    /// Parse profiles from an organization config section
    ///
    /// # Errors
    ///
    /// Will return `Err` if a role for the profile cannot be found
    pub fn try_from_spec(
        profile_config: &Spec,
        name: String,
        default_role: Option<String>,
        default_duration_seconds: Option<i32>,
    ) -> Result<Self> {
        let full_profile_config: FullSpec = profile_config.clone().into();

        Ok(Self {
            name,
            application_name: full_profile_config.application,
            role: full_profile_config
                .role
                .or(default_role)
                .ok_or_else(|| anyhow!("No role found"))?,
            duration_seconds: full_profile_config
                .duration_seconds
                .or(default_duration_seconds),
        })
    }

    #[instrument(skip(self, client), fields(organization=%client.base_url, profile=%self.name))]
    pub async fn into_credentials(self, client: &OktaClient) -> Result<Credentials> {
        let app_link = client
            .app_links(None)
            .await?
            .into_iter()
            .find(|app_link| {
                app_link.app_name == "amazon_aws" && app_link.label == self.application_name
            })
            .ok_or_else(|| anyhow!("Could not find Okta application for profile {}", self.name))?;

        let saml = client
            .get_saml_response(app_link.link_url)
            .await
            .map_err(|e| {
                anyhow!(
                    "Error getting SAML response for profile {} ({})",
                    self.name,
                    e
                )
            })?;

        let roles = saml.roles;

        let saml_role: SamlRole = roles
            .into_iter()
            .find(|r| r.role_name().map(|r| r == self.role).unwrap_or(false))
            .ok_or_else(|| {
                anyhow!(
                    "No matching role ({}) found for profile {}",
                    self.role,
                    &self.name
                )
            })?;

        trace!("Found role: {} for profile {}", saml_role.role, &self.name);

        let credentials = saml_role
            .assume(sts_client(), saml.raw, self.duration_seconds)
            .await
            .map_err(|e| anyhow!("Error assuming role for profile {} ({})", self.name, e))?;

        trace!("Credentials: {:?}", credentials);

        Ok(credentials)
    }
}
