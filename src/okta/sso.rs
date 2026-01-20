use std::sync::Arc;

use crate::{
    okta::applications::{AppLink, AppLinkAccountRoleMapping},
    okta::client::Client,
};

use cookie::Cookie;
use eyre::{Result, eyre};
use reqwest::cookie::{CookieStore, Jar};
use serde::Deserialize;
use tracing::trace;
use url::Url;

use crate::aws::sso::{AppInstance, Client as SsoClient};

pub struct SsoOrgAuth {
    pub org_id: String,
    pub auth_code: String,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RedirectState {
    pub url: Url,
    // pub method: String
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PresentationContext {
    // pub client_id: String,
    pub identity_pool_id: String,
    // pub username: String,
    // pub identity_pool_type: String,
    // pub application_type: String,
    // pub arn_partition: String,
    // pub locale: String,
    // pub airport_code: String
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct WorkflowState {
    // pub request_id: String,
    // pub step_id: String,
    pub redirect: RedirectState,
    pub presentation_context: PresentationContext,
    // pub workflow_response_data: serde_json::Value,
    // pub ping_location: Url,
}

impl Client {
    /// Extract `org_id` and `auth_code` from the platform-workflow-state cookie
    ///
    /// # Errors
    ///
    /// Will return `Err` if the cookie is not found or cannot be parsed
    fn extract_org_auth_from_cookie(cookies: &Arc<Jar>) -> Result<(String, String)> {
        let cookie_str = cookies
            .cookies(&Url::parse(
                "https://us-east-1.signin.aws.amazon.com/platform",
            )?)
            .ok_or_else(|| eyre!("No cookies found"))?;

        let workflow_state_cookie = Cookie::split_parse_encoded(cookie_str.to_str()?)
            .find(|c| c.as_ref().map(Cookie::name) == Ok("platform-workflow-state"))
            .transpose()?
            .ok_or_else(|| eyre!("platform-workflow-state cookie not found"))?;

        let workflow_state_str = workflow_state_cookie.value();
        let workflow_state: WorkflowState = serde_json::from_str(workflow_state_str)?;

        trace!(
            "Extracted org_id and auth_code from workflow state cookie: {:?}",
            workflow_state
        );

        let auth_code = workflow_state
            .redirect
            .url
            .query_pairs()
            .find(|(k, _)| k.eq("workflowResultHandle"))
            .ok_or_else(|| eyre!("No workflowResultHandle found in workflow state"))?
            .1
            .to_string();

        Ok((
            workflow_state.presentation_context.identity_pool_id,
            auth_code,
        ))
    }

    /// Extract `org_id` and `auth_code` from the AWS response URL
    ///
    /// # Errors
    ///
    /// Will return `Err` if the URL doesn't contain the required information
    fn extract_org_auth_from_url(aws_response: &reqwest::Response) -> Result<(String, String)> {
        let host = aws_response
            .url()
            .host()
            .ok_or_else(|| eyre!("No host found in response URL"))?;

        let org_id = if let url::Host::Domain(domain) = host {
            domain
                .split_once('.')
                .map(|(org, _)| org.to_string())
                .ok_or_else(|| eyre!("No dots found in domain: {:?}", domain))
        } else {
            Err(eyre!("Host: {:?} is not a domain", host))
        }?;

        let auth_code = aws_response
            .url()
            .query_pairs()
            .find(|(k, _)| k.eq("workflowResultHandle"))
            .ok_or_else(|| eyre!("No workflowResultHandle found in response URL"))?
            .1
            .to_string();

        trace!("Extracted org_id and auth_code from response URL");

        Ok((org_id, auth_code))
    }

    /// Given an `AppLink`, return the org Id and auth code needed to create an SSO client
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn get_org_auth_for_app_link(&self, app_link: AppLink) -> Result<SsoOrgAuth> {
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

        let cookies = Arc::from(Jar::default());
        let aws_response = reqwest::Client::builder()
            .cookie_provider(cookies.clone())
            .build()?
            .post(response.url.clone())
            .form(&[
                ("SAMLResponse", response.saml.clone()),
                ("RelayState", response.relay_state.clone()),
            ])
            .send()
            .await?;

        // Try cookie-based extraction first (newer AWS flow)
        let (org_id, auth_code) =
            Self::extract_org_auth_from_cookie(&cookies).or_else(|cookie_err| {
                trace!(
                    "Cookie extraction failed: {}, falling back to URL extraction",
                    cookie_err,
                );
                Self::extract_org_auth_from_url(&aws_response)
            })?;

        Ok(SsoOrgAuth { org_id, auth_code })
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
            account_id: app_instance.account_id().map(|id| id.to_string()),
        })
    }

    /// Given an `amazon_aws_sso` identity center `AppLink`, iterate through all app instances to get a list of all account names and roles that can be assumed.
    ///
    /// This function processes accounts in parallel batches of 10 to improve performance while avoiding rate limits.
    /// Progress is displayed to stderr showing which accounts are being processed (e.g., "Processing accounts 1-10/50...").
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub(crate) async fn get_sso_applink_accounts_and_roles(
        &self,
        app_link: AppLink,
    ) -> Result<Vec<AppLinkAccountRoleMapping>> {
        let app_name = app_link.clone().label;
        let org_auth = self.get_org_auth_for_app_link(app_link).await?;
        let sso_client = SsoClient::new(&org_auth.org_id, &org_auth.auth_code).await?;

        let app_instances = sso_client.app_instances().await?;
        let app_aws_accounts = app_instances
            .iter()
            .filter(|app_instance| app_instance.application_name == "AWS Account")
            .collect::<Vec<_>>();

        let total_accounts = app_aws_accounts.len();
        let mut all_account_role_mappings = Vec::new();
        let batch_size = 10; // Process 10 accounts in parallel to balance speed with rate limiting

        for (batch_num, chunk) in app_aws_accounts.chunks(batch_size).enumerate() {
            let batch_start = batch_num * batch_size + 1;
            let batch_end = std::cmp::min(batch_start + chunk.len() - 1, total_accounts);

            eprint!(
                "\r  Processing accounts {}-{}/{}... ",
                batch_start, batch_end, total_accounts
            );
            std::io::Write::flush(&mut std::io::stderr()).ok();

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

        eprintln!(
            "\r  Processed {}/{} accounts        ",
            total_accounts, total_accounts
        );
        Ok(all_account_role_mappings)
    }

    /// Given an identity center `AppLink`, return all app instances
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn all_app_instances(&self, app_link: AppLink) -> Result<Vec<AppInstance>> {
        let org_auth = self.get_org_auth_for_app_link(app_link).await?;
        let sso_client = SsoClient::new(&org_auth.org_id, &org_auth.auth_code).await?;

        sso_client.app_instances().await
    }
}
