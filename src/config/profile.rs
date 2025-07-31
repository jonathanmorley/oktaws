use mockall_double::double;

#[double]
use crate::okta::client::Client as OktaClient;
use crate::{
    aws::{sso::Client as SsoClient, sts_client},
    okta::applications::{AppLink, AppLinkAccountRoleMapping, IntegrationType},
    select,
};

use aws_credential_types::Credentials;
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use tracing::{instrument, trace};

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
    #[instrument(skip(mapping, default_roles))]
    pub fn from_account_mapping(
        mapping: AppLinkAccountRoleMapping,
        default_roles: &[String],
    ) -> Result<(String, Self)> {
        let default_roles_available = mapping
            .role_names
            .clone()
            .into_iter()
            .filter(|name| default_roles.contains(name))
            .collect::<Vec<_>>();

        let role_name = match mapping.role_names.len() {
            0 => Err(eyre!(
                "No profiles found for application {}",
                mapping.account_name
            )),
            1 => Ok(mapping.role_names.first().unwrap().to_string()),
            _ if default_roles_available.len() == 1 => {
                Ok(default_roles_available.first().unwrap().to_string())
            }
            _ if default_roles_available.len() > 1 => Ok(select(
                default_roles_available.clone(),
                format!("Choose Role for {}", mapping.account_name),
                std::clone::Clone::clone,
            )?),
            _ => Ok(select(
                mapping.role_names.clone(),
                format!("Choose Role for {}", mapping.account_name),
                std::clone::Clone::clone,
            )?),
        }?;
        let profile_config = if default_roles_available.contains(&role_name)
            && default_roles_available.len() == 1
            && mapping.integration_type == IntegrationType::Federated
        {
            Self::Name(mapping.application_name)
        } else if default_roles_available.contains(&role_name)
            && default_roles_available.len() == 1
            && mapping.integration_type == IntegrationType::IdentityCenter
        {
            Self::Detailed {
                application: mapping.application_name.clone(),
                account: Some(mapping.account_name.clone()),
                role: None,
                duration_seconds: None,
            }
        } else {
            Self::Detailed {
                application: mapping.application_name.clone(),
                account: Some(mapping.account_name.clone()),
                role: Some(role_name),
                duration_seconds: None,
            }
        };

        Ok((mapping.account_name, profile_config))
    }
}

/// This is a canonical representation of the Profile,
/// with required values resolved and defaults propagated.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Profile {
    pub name: String,
    pub application_name: String,
    pub account: Option<String>,
    pub roles: Vec<String>,
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
        default_roles: Option<Vec<String>>,
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
            roles: match profile_config {
                Config::Name(_) => None,
                Config::Detailed { role, .. } => role.clone().map(|r| vec![r]),
            }
            .or(default_roles)
            .ok_or_else(|| eyre!("No role found"))?,
            duration_seconds: match profile_config {
                Config::Name(_) => None,
                Config::Detailed {
                    duration_seconds, ..
                } => *duration_seconds,
            }
            .or(default_duration_seconds),
        })
    }

    #[instrument(skip(self, client), fields(organization=%client.base_url(), profile=%self.name))]
    pub async fn into_credentials(self, client: &OktaClient) -> Result<Credentials> {
        let saml_app_link = client.app_links(None).await?.into_iter().find(|app_link| {
            app_link.app_name == "amazon_aws" && app_link.label == self.application_name
        });

        if let Some(app_link) = saml_app_link {
            return self.into_saml_credentials(client, app_link).await;
        }

        let sso_app_link = client.app_links(None).await?.into_iter().find(|app_link| {
            app_link.app_name == "amazon_aws_sso" && app_link.label == self.application_name
        });

        if let Some(app_link) = sso_app_link {
            return self.into_sso_credentials(client, app_link).await;
        }

        Err(eyre!(
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
                eyre!(
                    "Error getting SAML response for profile {} ({})",
                    self.name,
                    e
                )
            })?;

        let saml_roles_available = response
            .roles()?
            .into_iter()
            .filter(|r| self.roles.contains(&r.role_name().unwrap()))
            .collect::<Vec<_>>();

        let saml_role = match saml_roles_available.len() {
            0 => Err(eyre!(
                "No roles found for profile {} in SAML response",
                self.name
            )),
            1 => Ok(saml_roles_available[0].clone()),
            _ => {
                let selected = select(
                    saml_roles_available,
                    format!("Choose Role for profile {}", self.name),
                    |role| role.role_name().unwrap(),
                )?;
                Ok(selected)
            }
        }?;

        trace!("Found role: {} for profile {}", saml_role.role, &self.name);

        let credentials = saml_role
            .assume(sts_client(), response.saml, self.duration_seconds)
            .await
            .map_err(|e| eyre!("Error assuming role for profile {} ({})", self.name, e))?;

        trace!("Credentials: {:?}", credentials);

        Ok(credentials)
    }

    async fn into_sso_credentials(
        self,
        client: &OktaClient,
        app_link: AppLink,
    ) -> Result<Credentials> {
        let org_auth = client
            .get_org_id_and_auth_code_for_app_link(app_link)
            .await?;

        let client = SsoClient::new(&org_auth.org_id, &org_auth.auth_code).await?;

        let app_instance = if let Some(account) = self.account {
            client
                .app_instances()
                .await?
                .into_iter()
                .find(|app| app.account_name() == Some(&account))
                .ok_or_else(|| eyre!("Could not find account: {account}"))
        } else {
            Err(eyre!("AWS SSO Applications must specify `account`"))
        }?;
        trace!("Found application: {:?}", app_instance);

        let account_id = app_instance
            .account_id()
            .ok_or_else(|| eyre!("No account ID found"))?;

        let profiles_available = client
            .profiles(&app_instance.id)
            .await?
            .into_iter()
            .filter(|profile| self.roles.contains(&profile.name))
            .collect::<Vec<_>>();

        let profile = match profiles_available.len() {
            0 => Err(eyre!(
                "No profiles found for application {}",
                app_instance.name
            )),
            1 => Ok(profiles_available[0].clone()),
            _ => {
                let selected = select(
                    profiles_available,
                    format!("Choose Profile for application {}", app_instance.name),
                    |profile| profile.name.clone(),
                )?;
                Ok(selected)
            }
        }?;

        trace!("Found profile: {:?}", profile);

        let credentials = client.credentials(account_id, &profile.name).await?;
        trace!("Credentials: {:?}", credentials);

        Ok(credentials)
    }
}
