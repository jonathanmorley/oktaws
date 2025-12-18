use eyre::{Result, eyre};
use regex::Regex;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::Deserialize;
use std::sync::LazyLock;
use std::time::Duration;
use std::time::SystemTime;
use tracing::{debug, trace};

const BASE_URL: &str = "https://portal.sso.us-east-1.amazonaws.com";

pub struct Client {
    token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub pagination_token: Option<String>,
    pub result: Vec<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInstance {
    pub id: String,
    pub name: String,
    pub description: String,
    pub application_id: String,
    pub application_name: String,
    pub icon: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub url: String,
    pub protocol: String,
    pub relay_state: Option<String>,
}

impl Client {
    /// # Errors
    ///
    /// The function will error for network issues, or if the response is not parseable as expected
    ///
    pub async fn new(org_id: &str, auth_code: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct SsoTokenResponse {
            token: String,
        }

        // Get SSO Token
        let response = reqwest::Client::new()
            .post(format!("{BASE_URL}/auth/sso-token"))
            .form(&[("authCode", auth_code), ("orgId", org_id)])
            .send()
            .await?;

        let text = response.text().await?;
        trace!("Received {}", &text);

        let SsoTokenResponse { token } = serde_json::from_str(&text)?;

        Ok(Self { token })
    }

    /// # Errors
    ///
    /// The function will error for network issues, or if the response is not parseable as expected
    ///
    pub async fn app_instances(&self) -> Result<Vec<AppInstance>> {
        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(Duration::from_secs(1), Duration::from_secs(2))
            .base(1)
            .build_with_max_retries(5);

        let client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        let response = client
            .get(format!("{BASE_URL}/instance/appinstances"))
            .header("x-amz-sso_bearer_token", &self.token)
            .header("x-amz-sso-bearer-token", &self.token)
            .send()
            .await?;

        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            Err(eyre!(
                "Error fetching app instances, StatusCode: {}, Response: {}",
                status,
                text
            ))?;
        }

        trace!("Received {}", &text);
        let Page::<AppInstance> { result, .. } = serde_json::from_str(&text)?;
        Ok(result)
    }

    /// # Errors
    ///
    /// The function will error for network issues, or if the response is not parseable as expected
    ///
    pub async fn profiles(&self, app_instance_id: &str) -> Result<Vec<Profile>> {
        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(Duration::from_secs(1), Duration::from_secs(2))
            .base(2)
            .build_with_max_retries(10);

        let client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        let response = client
            .get(format!(
                "{BASE_URL}/instance/appinstance/{app_instance_id}/profiles"
            ))
            .header("x-amz-sso_bearer_token", &self.token)
            .header("x-amz-sso-bearer-token", &self.token)
            .send()
            .await?;

        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            Err(eyre!(
                "Error fetching profiles, StatusCode: {}, Response: {}",
                status,
                text
            ))?;
        }

        trace!("Received {}", &text);
        let Page::<Profile> { result, .. } = serde_json::from_str(&text)?;
        Ok(result)
    }

    /// # Errors
    ///
    /// The function will error for network issues, or if the response is not parseable as expected
    ///
    pub async fn credentials(
        &self,
        account_id: &str,
        role_name: &str,
    ) -> Result<aws_credential_types::Credentials> {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Credentials {
            access_key_id: String,
            secret_access_key: String,
            session_token: String,
            expiration: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RoleCredentials {
            role_credentials: Credentials,
        }

        debug!("Requesting credentials for account: {account_id}, role: {role_name}");

        let RoleCredentials { role_credentials } = reqwest::Client::new()
            .get(format!("{BASE_URL}/federation/credentials/"))
            .query(&[
                ("account_id", account_id),
                ("role_name", role_name),
                ("debug", "true"),
            ])
            .header("x-amz-sso_bearer_token", &self.token)
            .header("x-amz-sso-bearer-token", &self.token)
            .send()
            .await?
            .json()
            .await?;

        Ok(aws_credential_types::Credentials::new(
            role_credentials.access_key_id,
            role_credentials.secret_access_key,
            Some(role_credentials.session_token),
            Some(SystemTime::UNIX_EPOCH + Duration::from_millis(role_credentials.expiration)),
            "oktaws",
        ))
    }
}

static ACCOUNT_NAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\((.+)\)").expect("Failed to compile account name regex"));

static ACCOUNT_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d+)").expect("Failed to compile account ID regex"));

impl AppInstance {
    #[must_use]
    pub fn account_name(&self) -> Option<String> {
        ACCOUNT_NAME_REGEX
            .captures(&self.name)
            .and_then(|captures| captures.get(1))
            .map(|mat| mat.as_str().to_lowercase().replace([' ', '_'], "-"))
    }

    #[must_use]
    pub fn account_id(&self) -> Option<&str> {
        ACCOUNT_ID_REGEX
            .captures(&self.name)
            .and_then(|captures| captures.get(1))
            .map(|mat| mat.as_str())
    }
}
