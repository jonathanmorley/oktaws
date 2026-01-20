use crate::{
    aws::{get_account_alias, saml::extract_account_name},
    okta::client::Client,
};

// Import sso module to make its Client impl methods available
#[allow(unused_imports)]
use crate::okta::sso;

use eyre::{Result, eyre};
use futures::future::join_all;
use serde::Deserialize;
use tracing::warn;
use url::Url;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppLink {
    pub label: String,
    pub link_url: Url,
    pub app_name: String,
}

#[derive(Clone, Debug)]
pub struct AppLinkAccountRoleMapping {
    pub account_name: String,
    pub role_names: Vec<String>,
    pub application_name: String,
    pub account_id: Option<String>,
}

impl Client {
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
            account_id: None,
        })
    }

    /// Given a list of `AppLink`s, visit each of them to get a list of all account names and roles that can be assumed.
    ///
    /// Supports both `amazon_aws` (federated) and `amazon_aws_sso` (identity center) apps.
    ///
    /// Processing strategy:
    /// - `amazon_aws` apps are processed in parallel (lightweight SAML requests)
    /// - `amazon_aws_sso` apps are processed sequentially to respect rate limits,
    ///   but each app's accounts are fetched in parallel batches internally
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn get_all_account_mappings(
        &self,
        links: Vec<AppLink>,
    ) -> Result<Vec<AppLinkAccountRoleMapping>> {
        let mut saml_role_futures = Vec::new();
        let mut all_role_names = Vec::new(); // SSO apps processed sequentially to respect rate limits
        for link in links {
            match link.app_name.as_str() {
                "amazon_aws" => {
                    saml_role_futures.push(self.get_saml_account_role_mapping(link));
                }
                "amazon_aws_sso" => {
                    all_role_names.extend(self.get_sso_applink_accounts_and_roles(link).await?);
                }
                _ => {
                    return Err(eyre!("Unsupported app name: {}", link.app_name));
                }
            }
        }
        let saml_roles = join_all(saml_role_futures)
            .await
            .into_iter()
            .collect::<Result<Vec<AppLinkAccountRoleMapping>>>()?;

        Ok([all_role_names, saml_roles].concat())
    }
}
