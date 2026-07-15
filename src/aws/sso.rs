use eyre::{Result, eyre};
use futures::future::join_all;
use regex::Regex;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::Deserialize;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, trace};

const BASE_URL: &str = "https://portal.sso.us-east-1.amazonaws.com";

fn retrying_client(max_retries: u32) -> ClientWithMiddleware {
    let retry_policy = ExponentialBackoff::builder()
        .retry_bounds(Duration::from_secs(1), Duration::from_secs(32))
        .base(2)
        .build_with_max_retries(max_retries);

    ClientBuilder::new(reqwest::Client::new())
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build()
}

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
    async fn fetch_all_accounts(
        &self,
        http: &ClientWithMiddleware,
        base_url: &str,
    ) -> Result<Vec<(String, String)>> {
        let mut accounts: Vec<(String, String)> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = http
                .get(format!("{base_url}/assignment/accounts"))
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
        http: ClientWithMiddleware,
        base_url: String,
        token: String,
        account_id: String,
        account_name: String,
    ) -> Result<PublicAccountRole> {
        let mut role_names: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = http
                .get(format!("{base_url}/assignment/roles"))
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
        let http = retrying_client(5);
        self.list_accounts_and_roles_with(&http, BASE_URL).await
    }

    async fn list_accounts_and_roles_with(
        &self,
        http: &ClientWithMiddleware,
        base_url: &str,
    ) -> Result<Vec<PublicAccountRole>> {
        let accounts = self.fetch_all_accounts(http, base_url).await?;
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
                        base_url.to_string(),
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
        let client = retrying_client(5);
        self.app_instances_with(&client, BASE_URL).await
    }

    async fn app_instances_with(
        &self,
        client: &ClientWithMiddleware,
        base_url: &str,
    ) -> Result<Vec<AppInstance>> {
        let mut all_instances = Vec::new();
        let mut pagination_token: Option<String> = None;

        loop {
            let url = format!("{base_url}/instance/appinstances");
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
        let client = retrying_client(10);

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
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fast_retrying_client(max_retries: u32) -> ClientWithMiddleware {
        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(Duration::from_millis(1), Duration::from_millis(2))
            .base(2)
            .build_with_max_retries(max_retries);

        ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build()
    }

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

    #[tokio::test]
    async fn test_list_accounts_and_roles_follows_all_pagination_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/assignment/accounts"))
            .and(header("x-amz-sso_bearer_token", "test-token"))
            .and(query_param_is_missing("next_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accountList": [{
                    "accountId": "111111111111",
                    "accountName": "Production Account"
                }],
                "nextToken": "accounts-page-2"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/assignment/accounts"))
            .and(header("x-amz-sso_bearer_token", "test-token"))
            .and(query_param("next_token", "accounts-page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accountList": [{
                    "accountId": "222222222222",
                    "accountName": "Shared_Services"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/assignment/roles"))
            .and(header("x-amz-sso_bearer_token", "test-token"))
            .and(query_param("account_id", "111111111111"))
            .and(query_param_is_missing("next_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "roleList": [{"roleName": "ReadOnly"}],
                "nextToken": "roles-page-2"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/assignment/roles"))
            .and(header("x-amz-sso_bearer_token", "test-token"))
            .and(query_param("account_id", "111111111111"))
            .and(query_param("next_token", "roles-page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "roleList": [
                    {"roleName": "AdminAccess"},
                    {"roleName": "ReadOnly"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/assignment/roles"))
            .and(header("x-amz-sso_bearer_token", "test-token"))
            .and(query_param("account_id", "222222222222"))
            .and(query_param_is_missing("next_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "roleList": [{"roleName": "PowerUser"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client {
            token: "test-token".to_string(),
        };
        let accounts = client
            .list_accounts_and_roles_with(&fast_retrying_client(1), &server.uri())
            .await
            .unwrap();

        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].account_id, "111111111111");
        assert_eq!(accounts[0].account_name, "production-account");
        assert_eq!(accounts[0].role_names, vec!["AdminAccess", "ReadOnly"]);
        assert_eq!(accounts[1].account_id, "222222222222");
        assert_eq!(accounts[1].account_name, "shared-services");
        assert_eq!(accounts[1].role_names, vec!["PowerUser"]);
    }

    #[tokio::test]
    async fn test_list_accounts_retries_transient_server_errors() {
        let server = MockServer::start().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let responder_attempts = Arc::clone(&attempts);

        Mock::given(method("GET"))
            .and(path("/assignment/accounts"))
            .and(header("x-amz-sso_bearer_token", "test-token"))
            .respond_with(move |_: &wiremock::Request| {
                if responder_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503)
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({"accountList": []}))
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        let client = Client {
            token: "test-token".to_string(),
        };
        let accounts = client
            .list_accounts_and_roles_with(&fast_retrying_client(1), &server.uri())
            .await
            .unwrap();

        assert!(accounts.is_empty());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_app_instances_follows_all_pagination_tokens() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/instance/appinstances"))
            .and(header("x-amz-sso_bearer_token", "test-token"))
            .and(query_param_is_missing("paginationToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "id": "instance-1",
                    "name": "111111111111 (Production)",
                    "description": "Production",
                    "applicationId": "application-1",
                    "applicationName": "AWS Account",
                    "icon": "icon-1"
                }],
                "paginationToken": "instances-page-2"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/instance/appinstances"))
            .and(header("x-amz-sso_bearer_token", "test-token"))
            .and(query_param("paginationToken", "instances-page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "id": "instance-2",
                    "name": "222222222222 (Development)",
                    "description": "Development",
                    "applicationId": "application-1",
                    "applicationName": "AWS Account",
                    "icon": "icon-2"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client {
            token: "test-token".to_string(),
        };
        let instances = client
            .app_instances_with(&fast_retrying_client(1), &server.uri())
            .await
            .unwrap();

        assert_eq!(
            instances
                .iter()
                .map(|instance| instance.id.as_str())
                .collect::<Vec<_>>(),
            vec!["instance-1", "instance-2"]
        );
    }
}
