use crate::{
    aws::{get_account_alias, saml::extract_account_name},
    okta::client::Client,
};

use eyre::{eyre, Result};
use futures::future::join_all;
use serde::Deserialize;
use tracing::warn;
use url::Url;

use crate::aws::sso::{AppInstance, Client as SsoClient};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppLink {
    pub label: String,
    pub link_url: Url,
    pub app_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrationType {
    Federated,
    IdentityCenter,
}

#[derive(Clone, Debug)]
pub struct AppLinkAccountRoleMapping {
    pub account_name: String,
    pub role_names: Vec<String>,
    pub application_name: String,
    pub integration_type: IntegrationType,
}

pub struct SsoOrgAuth {
    pub org_id: String,
    pub auth_code: String,
}

impl Client {
    /// Given an `AppLink`, return the org Id and auth code needed to create an SSO client
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn get_org_id_and_auth_code_for_app_link(
        &self,
        app_link: AppLink,
    ) -> Result<SsoOrgAuth> {
        let response = self
            .get_saml_response(app_link.link_url)
            .await
            .map_err(|e| {
                eyre!(
                    "Error getting SAML response for app link {} ({})",
                    app_link.label,
                    e
                )
            })?;

        let response = response.post().await?;
        let host = response
            .url()
            .host()
            .ok_or_else(|| eyre!("No host found"))?;
        let org_id = if let url::Host::Domain(domain) = host {
            domain
                .split_once('.')
                .map(|(org, _)| org)
                .ok_or_else(|| eyre!("No dots found in domain: {:?}", domain))
        } else {
            Err(eyre!("Host: {:?} is not a domain", host))
        }?;
        let auth_code = response
            .url()
            .query_pairs()
            .find(|(k, _)| k.eq("workflowResultHandle"))
            .ok_or_else(|| eyre!("No token found"))?
            .1;

        Ok(SsoOrgAuth {
            org_id: (org_id.to_string()),
            auth_code: (auth_code.to_string()),
        })
    }

    /// Return all the `AppLink`s for a given user.
    /// If `user_id` is None, assume the current user.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any network errors encountered
    pub async fn app_links(&self, user_id: Option<&str>) -> Result<Vec<AppLink>> {
        self.get(&format!(
            "api/v1/users/{}/appLinks",
            user_id.unwrap_or("me")
        ))
        .await
    }

    /// Given an `amazon_aws` federated `AppLink`, visit it to get the account name and roles that can be assumed
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn get_saml_account_role_mapping(
        &self,
        link: AppLink,
    ) -> Result<AppLinkAccountRoleMapping> {
        let response = self.get_saml_response(link.link_url).await?;
        let aws_response = match response.clone().post().await {
            Err(e) => {
                warn!("Caught error trying to login to AWS: {}, trying again", e);
                response.clone().post().await
            }
            ok => ok,
        }?;

        let aws_response_text = aws_response.text().await?;
        let roles = response.clone().roles()?;

        if roles.is_empty() {
            return Err(eyre!("No roles found for app link: {}", link.label));
        }

        let mut role_names = roles
            .clone()
            .into_iter()
            .map(|role| {
                role.role_name().unwrap_or_else(|_| {
                    warn!("No role name found for role: {:?}", role);
                    "Unknown Role".to_string()
                })
            })
            .collect::<Vec<_>>();
        role_names.sort();

        let account_name = get_account_alias(&roles[0].clone(), &response)
            .await
            .or_else(|_| extract_account_name(&aws_response_text))
            .unwrap_or_else(|_| {
                warn!("No AWS account alias found. Falling back on Okta Application name");
                link.label.clone()
            });

        let application_name = link.label.clone();

        Ok(AppLinkAccountRoleMapping {
            account_name,
            role_names,
            application_name,
            integration_type: IntegrationType::Federated,
        })
    }

    /// Given an `amazon_aws_sso` identity center `AppInstance`, visit it to get the account name and roles that can be assumed
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    async fn get_sso_account_role_mapping(
        &self,
        app_instance: &AppInstance,
        application_name: String,
        sso_client: &SsoClient,
    ) -> Result<AppLinkAccountRoleMapping> {
        let profiles = sso_client.profiles(&app_instance.id).await?;

        if profiles.is_empty() {
            return Err(eyre!(
                "No roles found for app instance: {}",
                app_instance.name
            ));
        }

        let mut role_names = profiles.iter().map(|p| p.name.clone()).collect::<Vec<_>>();
        role_names.sort();
        let account_name = app_instance.account_name().ok_or_else(|| {
            eyre!(
                "No account name found for app instance: {}",
                app_instance.name
            )
        })?;

        Ok(AppLinkAccountRoleMapping {
            account_name,
            role_names,
            application_name,
            integration_type: IntegrationType::IdentityCenter,
        })
    }

    /// Given an `amazon_aws_sso` identity center `AppLink`, iterate through all app instances to get a list of all account names and roles that can be assumed
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn get_sso_applink_accounts_and_roles(
        &self,
        app_link: AppLink,
    ) -> Result<Vec<AppLinkAccountRoleMapping>> {
        let app_name = app_link.clone().label;
        let org_auth = self.get_org_id_and_auth_code_for_app_link(app_link).await?;
        let sso_client = SsoClient::new(&org_auth.org_id, &org_auth.auth_code).await?;

        let app_instances = sso_client.app_instances().await?;
        let app_aws_accounts = app_instances
            .iter()
            .filter(|app_instance| app_instance.application_name == "AWS Account")
            .collect::<Vec<_>>();

        let mut all_account_role_mappings = Vec::new();
        let batch_size = 5;
        for chunk in app_aws_accounts.chunks(batch_size) {
            let mut futures = Vec::new();
            for app_aws_account in chunk {
                futures.push(self.get_sso_account_role_mapping(
                    app_aws_account,
                    app_name.clone(),
                    &sso_client,
                ));
            }
            let nested_account_role_mappings = futures::future::join_all(futures).await;
            let account_role_mappings = nested_account_role_mappings
                .into_iter()
                .collect::<Result<Vec<AppLinkAccountRoleMapping>>>()?;
            all_account_role_mappings.extend(account_role_mappings);
        }
        Ok(all_account_role_mappings)
    }

    /// Given a list of `AppLink`s, visit each of them to get a list of all account names and roles that can be assumed
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn get_all_account_mappings(
        &self,
        links: Vec<AppLink>,
    ) -> Result<Vec<AppLinkAccountRoleMapping>> {
        let mut saml_role_futures = Vec::new();
        let mut all_role_names = Vec::new(); // We don't want to run sso app links concurrently due to rate limiting
        for link in links {
            if link.app_name == "amazon_aws" {
                saml_role_futures.push(self.get_saml_account_role_mapping(link));
            } else if link.app_name == "amazon_aws_sso" {
                all_role_names.extend(self.get_sso_applink_accounts_and_roles(link).await?);
            } else {
                return Err(eyre!("Unsupported app name: {}", link.app_name));
            }
        }
        let saml_roles = join_all(saml_role_futures)
            .await
            .into_iter()
            .collect::<Result<Vec<AppLinkAccountRoleMapping>>>()?;

        Ok([all_role_names, saml_roles].concat())
    }

    /// Given an identity center `AppLink`, return all app instances
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn all_app_instances(&self, app_link: AppLink) -> Result<Vec<AppInstance>> {
        let org_auth = self.get_org_id_and_auth_code_for_app_link(app_link).await?;
        let sso_client = SsoClient::new(&org_auth.org_id, &org_auth.auth_code).await?;

        sso_client.app_instances().await
    }

    /// Given an array of `AppLinkAccountMapping`s, remove any mappings that have overlapping sso and saml account names.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while removing overlapped accounts.
    pub fn remove_overlapped_account_mappings(
        &self,
        account_mappings: Vec<AppLinkAccountRoleMapping>,
    ) -> Result<Vec<AppLinkAccountRoleMapping>> {
        let mut saml_account_names = std::collections::HashSet::new();
        let mut sso_account_names = std::collections::HashSet::new();

        for mapping in &account_mappings {
            match mapping.integration_type {
                IntegrationType::Federated => {
                    saml_account_names.insert(mapping.account_name.clone());
                }
                IntegrationType::IdentityCenter => {
                    sso_account_names.insert(mapping.account_name.clone());
                }
            }
        }

        let overlap: Vec<_> = saml_account_names
            .intersection(&sso_account_names)
            .cloned()
            .collect();

        let filtered_account_role_mappings = if overlap.is_empty() {
            account_mappings
        } else {
            let options = &["Identity Center", "Account Federation"];

            let favored_integration = dialoguer::Select::new()
                .with_prompt(
                    "Overlapping accounts found in Identity Center and Federated AWS Account tiles. Which integration type do you want to favor?"
                )
                .items(options)
                .default(0)
                .interact()?;

            match favored_integration {
                0 => {
                    // Favor Identity Center: remove overlapped account mappings with Federated type
                    account_mappings
                        .into_iter()
                        .filter(|mapping| {
                            !(overlap.contains(&mapping.account_name)
                                && mapping.integration_type == IntegrationType::Federated)
                        })
                        .collect()
                }
                1 => {
                    // Favor Account Federation: remove overlapped account mappings with Identity Center types
                    account_mappings
                        .into_iter()
                        .filter(|mapping| {
                            !(overlap.contains(&mapping.account_name)
                                && mapping.integration_type == IntegrationType::IdentityCenter)
                        })
                        .collect()
                }
                _ => account_mappings,
            }
        };

        Ok(filtered_account_role_mappings)
    }
}
