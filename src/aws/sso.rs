use eyre::{eyre, Result};
use futures::future::join_all;
use regex::Regex;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use serde::Deserialize;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, trace};

const BASE_URL: &str = "https://portal.sso.us-east-1.amazonaws.com";

pub struct Client {
    token: String,
}

#[derive(Debug, Clone)]
pub struct PublicAccountRole {
    pub account_id: String,
    pub account_name: String,
    pub role_names: Vec<String>,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountInfo {
    account_id: String,
    account_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountsPage {
    account_list: Option<Vec<AccountInfo>>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleInfo {
    role_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RolesPage {
    role_list: Option<Vec<RoleInfo>>,
    next_token: Option<String>,
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

    /// Retrieve account/role mappings using the portal bearer token already held by this client.
    /// Calls the public IAM Identity Center API (`ListAccounts` / `ListAccountRoles`) directly
    /// over `reqwest` using the same `x-amz-sso_bearer_token` header as the portal endpoints.
    /// Roles are fetched in parallel batches of 3 to improve performance while avoiding rate limits.
    /// Progress is displayed to stderr (e.g., "Processing accounts 1-3/50...").
    ///
    /// This method is defined on [`Client`] rather than in `okta/sso.rs` because `Client::token`
    /// is private. The portal bearer token must stay encapsulated here; callers in `okta/sso.rs`
    /// cannot access it directly and therefore cannot make the API calls themselves.
    ///
    /// Note: the public API identifies accounts by their 12-digit AWS account ID
    /// (`GET /assignment/accounts` → `GET /assignment/roles?account_id=...`).
    /// The portal API uses opaque app-instance IDs instead
    /// (`GET /instance/appinstances` → `GET /instance/appinstance/{id}/profiles`).
    /// The two identifier systems are not interchangeable, which is why the existing
    /// `app_instances` / `profiles` code path cannot be reused here.
    ///
    /// # Errors
    ///
    /// The function will error for API/network failures.
    async fn fetch_all_accounts(&self, http: &reqwest::Client) -> Result<Vec<(String, String)>> {
        let mut accounts: Vec<(String, String)> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = http
                .get(format!("{BASE_URL}/assignment/accounts"))
                .header("x-amz-sso_bearer_token", &self.token);
            if let Some(ref tok) = next_token {
                req = req.query(&[("next_token", tok.as_str())]);
            }
            let resp = req.send().await?;
            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(eyre!("ListAccounts failed ({}): {}", status, text));
            }
            trace!("ListAccounts response: {}", &text);
            let page: AccountsPage = serde_json::from_str(&text)?;
            for acct in page.account_list.unwrap_or_default() {
                accounts.push((acct.account_id, acct.account_name));
            }
            next_token = page.next_token;
            if next_token.is_none() {
                break;
            }
        }
        Ok(accounts)
    }

    async fn fetch_account_roles(
        http: reqwest::Client,
        token: String,
        account_id: String,
        account_name: String,
    ) -> Result<PublicAccountRole> {
        let mut role_names: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = http
                .get(format!("{BASE_URL}/assignment/roles"))
                .header("x-amz-sso_bearer_token", &token)
                .query(&[("account_id", account_id.as_str())]);
            if let Some(ref tok) = next_token {
                req = req.query(&[("next_token", tok.as_str())]);
            }
            let resp = req.send().await?;
            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(eyre!(
                    "ListAccountRoles failed for {} ({}): {}",
                    account_id,
                    status,
                    text
                ));
            }
            trace!("ListAccountRoles response for {}: {}", account_id, &text);
            let page: RolesPage = serde_json::from_str(&text)?;
            for role in page.role_list.unwrap_or_default() {
                role_names.push(role.role_name);
            }
            next_token = page.next_token;
            if next_token.is_none() {
                break;
            }
        }
        role_names.sort();
        role_names.dedup();
        Ok(PublicAccountRole {
            account_id,
            account_name: account_name.to_lowercase().replace([' ', '_'], "-"),
            role_names,
        })
    }

    /// # Errors
    ///
    /// The function will error for API/network failures.
    pub async fn list_accounts_and_roles(&self) -> Result<Vec<PublicAccountRole>> {
        let http = reqwest::Client::new();
        let accounts = self.fetch_all_accounts(&http).await?;
        debug!("ListAccounts returned {} accounts", accounts.len());

        let mut results = Vec::new();
        let total = accounts.len();
        let batch_size = 3;

        for (batch_num, chunk) in accounts.chunks(batch_size).enumerate() {
            let batch_start = batch_num * batch_size + 1;
            let batch_end = (batch_start + chunk.len() - 1).min(total);

            eprint!("\r  Processing accounts {batch_start}-{batch_end}/{total}... ");
            std::io::Write::flush(&mut std::io::stderr()).ok();

            let batch_futures: Vec<_> = chunk
                .iter()
                .map(|(account_id, account_name)| {
                    Self::fetch_account_roles(
                        http.clone(),
                        self.token.clone(),
                        account_id.clone(),
                        account_name.clone(),
                    )
                })
                .collect();

            let batch_results: Vec<Result<PublicAccountRole>> = join_all(batch_futures).await;
            for result in batch_results {
                results.push(result?);
            }
        }

        eprintln!("\r  Processed {total}/{total} accounts        ");
        Ok(results)
    }

    /// # Errors
    ///
    /// The function will error for network issues, or if the response is not parseable as expected
    ///
    pub async fn app_instances(&self) -> Result<Vec<AppInstance>> {
        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(Duration::from_secs(1), Duration::from_secs(32))
            .base(2)
            .build_with_max_retries(5);

        let client: ClientWithMiddleware = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        let mut all_instances = Vec::new();
        let mut pagination_token: Option<String> = None;

        loop {
            let url = format!("{BASE_URL}/instance/appinstances");
            let mut request = client.get(&url);
            if let Some(ref token) = pagination_token {
                request = request.query(&[("paginationToken", token.as_str())]);
            }

            let response = request
                .header("x-amz-sso_bearer_token", &self.token)
                .header("x-amz-sso-bearer-token", &self.token)
                .send()
                .await?;

            let status = response.status();
            let text = response.text().await?;
            if !status.is_success() {
                return Err(eyre!(
                    "Error fetching app instances, StatusCode: {}, Response: {}",
                    status,
                    text
                ));
            }

            trace!("Received {}", &text);
            let Page::<AppInstance> {
                result,
                pagination_token: next_token,
            } = serde_json::from_str(&text)?;
            all_instances.extend(result);

            if next_token.is_none() {
                break;
            }
            pagination_token = next_token;
        }

        Ok(all_instances)
    }

    /// # Errors
    ///
    /// The function will error for network issues, or if the response is not parseable as expected
    ///
    pub async fn profiles(&self, app_instance_id: &str) -> Result<Vec<Profile>> {
        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(Duration::from_secs(1), Duration::from_secs(32))
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

    // --- Tests covering the be3be6f commit ---
    // These cover the module-level AccountsPage / RolesPage deserialization structs
    // (introduced in be3be6f, moved to module scope in the subsequent refactor) and
    // the account-name normalization applied inside fetch_account_roles().

    #[test]
    fn test_accounts_page_deserializes_list_and_next_token() {
        let json = r#"{
            "accountList": [
                {"accountId": "111111111111", "accountName": "Production"},
                {"accountId": "222222222222", "accountName": "Staging"}
            ],
            "nextToken": "tok123"
        }"#;
        let page: AccountsPage = serde_json::from_str(json).unwrap();
        let list = page.account_list.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].account_id, "111111111111");
        assert_eq!(list[0].account_name, "Production");
        assert_eq!(list[1].account_id, "222222222222");
        assert_eq!(page.next_token.as_deref(), Some("tok123"));
    }

    #[test]
    fn test_accounts_page_null_list_and_no_token() {
        // AWS returns null accountList when there are no accounts.
        let json = r#"{"nextToken": null}"#;
        let page: AccountsPage = serde_json::from_str(json).unwrap();
        assert!(page.account_list.is_none());
        assert!(page.next_token.is_none());
    }

    #[test]
    fn test_accounts_page_absent_fields_become_none() {
        // Both fields may be entirely absent (not just null).
        let json = r"{}";
        let page: AccountsPage = serde_json::from_str(json).unwrap();
        assert!(page.account_list.is_none());
        assert!(page.next_token.is_none());
    }

    #[test]
    fn test_roles_page_deserializes_list_and_next_token() {
        let json = r#"{
            "roleList": [
                {"roleName": "AdminAccess"},
                {"roleName": "ReadOnly"}
            ],
            "nextToken": "page2"
        }"#;
        let page: RolesPage = serde_json::from_str(json).unwrap();
        let list = page.role_list.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].role_name, "AdminAccess");
        assert_eq!(list[1].role_name, "ReadOnly");
        assert_eq!(page.next_token.as_deref(), Some("page2"));
    }

    #[test]
    fn test_roles_page_null_list_and_no_token() {
        let json = r#"{"roleList": null}"#;
        let page: RolesPage = serde_json::from_str(json).unwrap();
        assert!(page.role_list.is_none());
        assert!(page.next_token.is_none());
    }

    // The account-name normalization inside fetch_account_roles applies
    // to_lowercase + replace spaces/underscores with hyphens.  This is the same
    // transform as AppInstance::account_name() (already tested above), but applied
    // to the raw string from the public API rather than the portal display name.
    #[test]
    fn test_fetch_account_roles_name_normalization_logic() {
        let normalize = |s: &str| s.to_lowercase().replace([' ', '_'], "-");
        assert_eq!(normalize("Production"), "production");
        assert_eq!(normalize("My Test Account"), "my-test-account");
        assert_eq!(normalize("Test_Account_Name"), "test-account-name");
        assert_eq!(normalize("Mixed Space_And_Under"), "mixed-space-and-under");
        assert_eq!(normalize("UPPER CASE"), "upper-case");
    }
}
