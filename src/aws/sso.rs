use eyre::{Result, eyre};
use regex::Regex;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::Deserialize;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::trace;

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

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create test AppInstance
    fn create_test_instance(name: &str) -> AppInstance {
        AppInstance {
            id: "test-id".to_string(),
            name: name.to_string(),
            description: "Test description".to_string(),
            application_id: "test-app-id".to_string(),
            application_name: "AWS Account".to_string(),
            icon: "test-icon".to_string(),
        }
    }

    // Tests for account_name()
    #[test]
    fn test_account_name_basic() {
        let instance = create_test_instance("123456789012 (Production Account)");
        assert_eq!(
            instance.account_name(),
            Some("production-account".to_string())
        );
    }

    #[test]
    fn test_account_name_with_spaces() {
        let instance = create_test_instance("123456789012 (My Test Account)");
        assert_eq!(instance.account_name(), Some("my-test-account".to_string()));
    }

    #[test]
    fn test_account_name_with_underscores() {
        let instance = create_test_instance("123456789012 (Test_Account_Name)");
        assert_eq!(
            instance.account_name(),
            Some("test-account-name".to_string())
        );
    }

    #[test]
    fn test_account_name_mixed_spaces_underscores() {
        let instance = create_test_instance("123456789012 (Test Account_Name)");
        assert_eq!(
            instance.account_name(),
            Some("test-account-name".to_string())
        );
    }

    #[test]
    fn test_account_name_uppercase() {
        let instance = create_test_instance("123456789012 (PRODUCTION)");
        assert_eq!(instance.account_name(), Some("production".to_string()));
    }

    #[test]
    fn test_account_name_mixed_case() {
        let instance = create_test_instance("123456789012 (PrOdUcTiOn)");
        assert_eq!(instance.account_name(), Some("production".to_string()));
    }

    #[test]
    fn test_account_name_no_parentheses() {
        let instance = create_test_instance("123456789012 Production");
        assert_eq!(instance.account_name(), None);
    }

    #[test]
    fn test_account_name_empty_parentheses() {
        let instance = create_test_instance("123456789012 ()");
        // Empty parentheses don't match the regex (no content captured)
        assert_eq!(instance.account_name(), None);
    }

    #[test]
    fn test_account_name_nested_parentheses() {
        let instance = create_test_instance("123456789012 (Prod (Main))");
        assert_eq!(instance.account_name(), Some("prod-(main)".to_string()));
    }

    #[test]
    fn test_account_name_only_parentheses() {
        let instance = create_test_instance("(Production)");
        assert_eq!(instance.account_name(), Some("production".to_string()));
    }

    #[test]
    fn test_account_name_multiple_parentheses() {
        let instance = create_test_instance("123456789012 (Prod) (Test)");
        // Regex pattern \((.+)\) is greedy and captures everything between first ( and last )
        assert_eq!(instance.account_name(), Some("prod)-(test".to_string()));
    }

    #[test]
    fn test_account_name_special_chars_in_name() {
        let instance = create_test_instance("123456789012 (Test-Account.Name)");
        assert_eq!(
            instance.account_name(),
            Some("test-account.name".to_string())
        );
    }

    // Tests for account_id()
    #[test]
    fn test_account_id_basic() {
        let instance = create_test_instance("123456789012 (Production)");
        assert_eq!(instance.account_id(), Some("123456789012"));
    }

    #[test]
    fn test_account_id_12_digits() {
        let instance = create_test_instance("999888777666 (Test)");
        assert_eq!(instance.account_id(), Some("999888777666"));
    }

    #[test]
    fn test_account_id_only() {
        let instance = create_test_instance("123456789012");
        assert_eq!(instance.account_id(), Some("123456789012"));
    }

    #[test]
    fn test_account_id_with_extra_digits() {
        let instance = create_test_instance("1234567890123 (Test)");
        // Regex captures first 12+ consecutive digits from start
        assert_eq!(instance.account_id(), Some("1234567890123"));
    }

    #[test]
    fn test_account_id_no_leading_digits() {
        let instance = create_test_instance("Account 123456789012");
        assert_eq!(instance.account_id(), None);
    }

    #[test]
    fn test_account_id_partial_digits() {
        let instance = create_test_instance("12345 (Test)");
        assert_eq!(instance.account_id(), Some("12345"));
    }

    #[test]
    fn test_account_id_no_digits() {
        let instance = create_test_instance("(Production Account)");
        assert_eq!(instance.account_id(), None);
    }

    #[test]
    fn test_account_id_digits_after_space() {
        let instance = create_test_instance(" 123456789012 (Test)");
        assert_eq!(instance.account_id(), None);
    }

    // Combined tests
    #[test]
    fn test_both_account_name_and_id() {
        let instance = create_test_instance("123456789012 (Production Account)");
        assert_eq!(instance.account_id(), Some("123456789012"));
        assert_eq!(
            instance.account_name(),
            Some("production-account".to_string())
        );
    }

    #[test]
    fn test_neither_account_name_nor_id() {
        let instance = create_test_instance("Invalid Format");
        assert_eq!(instance.account_id(), None);
        assert_eq!(instance.account_name(), None);
    }

    #[test]
    fn test_id_only_no_name() {
        let instance = create_test_instance("123456789012");
        assert_eq!(instance.account_id(), Some("123456789012"));
        assert_eq!(instance.account_name(), None);
    }

    #[test]
    fn test_name_only_no_id() {
        let instance = create_test_instance("(Production Account)");
        assert_eq!(instance.account_id(), None);
        assert_eq!(
            instance.account_name(),
            Some("production-account".to_string())
        );
    }
}
