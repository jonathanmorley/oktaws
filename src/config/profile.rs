use crate::{
    aws::saml::extract_account_name,
    aws::sso::Client as SsoClient,
    aws::{get_account_alias, sts_client},
    okta::applications::AppLink,
    okta::client::Client as OktaClient,
    select,
};

use anyhow::{anyhow, Result};
use aws_types::Credentials;
use serde::{Deserialize, Serialize};
use tracing::{instrument, trace, warn};

/// This is an intentionally 'loose' struct,
/// representing the potential various ways of providing a profile.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Config {
    Name(String),
    Detailed {
        application: String,
        account: Option<String>,
        role: Option<String>,
        duration_seconds: Option<i32>,
    },
}

impl Config {
    #[instrument(skip(client, link, default_role), fields(organization=%client.base_url, application=%link.label))]
    pub async fn from_app_link(
        client: &OktaClient,
        link: AppLink,
        default_role: Option<String>,
    ) -> Result<(String, Self)> {
        let response = client.get_saml_response(link.link_url).await?;
        let aws_response = match response.clone().post().await {
            Err(e) => {
                warn!("Caught error trying to login to AWS: {}, trying again", e);
                response.clone().post().await
            }
            ok => ok,
        }?;
        let aws_response_text = aws_response.text().await?;

        let roles = response.clone().roles()?;

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
            Self::Detailed {
                application: link.label,
                account: None,
                role: Some(role_name),
                duration_seconds: None,
            }
        };

        Ok((account_name, profile_config))
    }
}

/// This is a canonical representation of the Profile,
/// with required values resolved and defaults propagated.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Profile {
    pub name: String,
    pub application_name: String,
    pub account: Option<String>,
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
        profile_config: &Config,
        name: String,
        default_role: Option<String>,
        default_duration_seconds: Option<i32>,
    ) -> Result<Self> {
        Ok(Self {
            name,
            application_name: match profile_config {
                Config::Name(name) => name,
                Config::Detailed { application, .. } => application,
            }
            .clone(),
            account: match profile_config {
                Config::Name(_) => None,
                Config::Detailed { account, .. } => account.clone(),
            },
            role: match profile_config {
                Config::Name(_) => None,
                Config::Detailed { role, .. } => role.clone(),
            }
            .or(default_role)
            .ok_or_else(|| anyhow!("No role found"))?,
            duration_seconds: match profile_config {
                Config::Name(_) => None,
                Config::Detailed {
                    duration_seconds, ..
                } => *duration_seconds,
            }
            .or(default_duration_seconds),
        })
    }

    #[instrument(skip(self, client), fields(organization=%client.base_url, profile=%self.name))]
    pub async fn into_credentials(self, client: &OktaClient) -> Result<Credentials> {
        let saml_app_link = client.app_links(None).await?.into_iter().find(|app_link| {
            app_link.app_name == "amazon_aws" && app_link.label == self.application_name
        });

        if let Some(app_link) = saml_app_link {
            return self.into_saml_credentials(client, app_link).await;
        };

        let sso_app_link = client.app_links(None).await?.into_iter().find(|app_link| {
            app_link.app_name == "amazon_aws_sso" && app_link.label == self.application_name
        });

        if let Some(app_link) = sso_app_link {
            return self.into_sso_credentials(client, app_link).await;
        }

        Err(anyhow!(
            "Could not find Okta application for profile {}",
            self.name
        ))
    }

    async fn into_saml_credentials(
        self,
        client: &OktaClient,
        app_link: AppLink,
    ) -> Result<Credentials> {
        let response = client
            .get_saml_response(app_link.link_url)
            .await
            .map_err(|e| {
                anyhow!(
                    "Error getting SAML response for profile {} ({})",
                    self.name,
                    e
                )
            })?;

        let saml_role = response
            .roles()?
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
            .assume(sts_client(), response.saml, self.duration_seconds)
            .await
            .map_err(|e| anyhow!("Error assuming role for profile {} ({})", self.name, e))?;

        trace!("Credentials: {:?}", credentials);

        Ok(credentials)
    }

    async fn into_sso_credentials(
        self,
        client: &OktaClient,
        app_link: AppLink,
    ) -> Result<Credentials> {
        let response = client
            .get_saml_response(app_link.link_url)
            .await
            .map_err(|e| {
                anyhow!(
                    "Error getting SAML response for profile {} ({})",
                    self.name,
                    e
                )
            })?;

        let response = response.post().await?;
        let host = response
            .url()
            .host()
            .ok_or_else(|| anyhow!("No host found"))?;
        let org_id = if let url::Host::Domain(domain) = host {
            domain
                .split_once('.')
                .map(|(org, _)| org)
                .ok_or_else(|| anyhow!("No dots found in domain: {:?}", domain))
        } else {
            Err(anyhow!("Host: {:?} is not a domain", host))
        }?;
        let auth_code = response
            .url()
            .query_pairs()
            .find(|(k, _)| k.eq("workflowResultHandle"))
            .ok_or_else(|| anyhow!("No token found"))?
            .1;

        let client = SsoClient::new(org_id, &auth_code).await?;

        let app_instance = if let Some(account) = self.account {
            client
                .app_instances()
                .await?
                .into_iter()
                .find(|app| app.account_name() == Some(&account))
                .ok_or_else(|| anyhow!("Could not find account: {account}"))
        } else {
            Err(anyhow!("AWS SSO Applications must specify `account`"))
        }?;
        trace!("Found application: {:?}", app_instance);

        let account_id = app_instance
            .account_id()
            .ok_or_else(|| anyhow!("No account ID found"))?;

        let profile = client
            .profiles(&app_instance.id)
            .await?
            .into_iter()
            .find(|profile| profile.name == self.role)
            .ok_or_else(|| anyhow!("Cound not find profile: {}", self.role))?;
        trace!("Found profile: {:?}", profile);

        let credentials = client.credentials(account_id, &profile.name).await?;
        trace!("Credentials: {:?}", credentials);

        Ok(credentials)
    }
}
