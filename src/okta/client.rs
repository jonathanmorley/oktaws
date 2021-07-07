use crate::okta::auth::LoginRequest;

use std::collections::HashSet;
use std::sync::Arc;

use dialoguer::Password;
use failure::Error;
#[cfg(not(target_os = "linux"))]
use keyring::Keyring;
use reqwest::cookie::Jar;
use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Client as HttpClient;
use reqwest::Response;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

pub struct Client {
    client: HttpClient,
    base_url: Url,
    pub cookies: Arc<Jar>,
}

#[derive(Deserialize, Debug, Fail, Serialize)]
#[serde(rename_all = "camelCase")]
#[fail(display = "{}: {}", error_code, error_summary)]
pub struct ClientError {
    error_code: String,
    error_summary: String,
    error_link: String,
    error_id: String,
    error_causes: Option<Vec<ClientErrorSummary>>,
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientErrorSummary {
    error_summary: String,
}

impl Client {
    pub async fn new(
        organization: String,
        username: String,
        force_prompt: bool,
    ) -> Result<Self, Error> {
        let mut base_url = Url::parse(&format!("https://{}.okta.com/", organization))?;
        base_url
            .set_username(&username)
            .map_err(|_| format_err!("Cannot set username for URL"))?;

        let cookies = Arc::from(Jar::default());

        let service = format!("oktaws::okta::{}", organization);

        let mut client = Client {
            client: HttpClient::builder()
                .cookie_store(true)
                .cookie_provider(cookies.clone())
                .build()?,
            base_url: base_url.clone(),
            cookies,
        };

        // Visit the homepage to get a DeviceToken (DT) cookie (used for persisting MFA information).
        client.get_response(base_url).await?;

        // get password
        #[cfg(not(target_os = "linux"))]
        let keyring = Keyring::new(&service, &username);

        #[cfg(not(target_os = "linux"))]
        let password = client.get_password(&keyring, force_prompt)?;
        #[cfg(target_os = "linux")]
        let password = client.prompt_password()?;

        let login_request = LoginRequest::from_credentials(
            username.to_owned(),
            password.clone(),
        );

        // Do the login
        let session_token = match client.get_session_token(&login_request).await {
            Ok(session_token) => {
                // Save the password.
                #[cfg(not(target_os = "linux"))]
                client.set_cached_password(&keyring, &password);

                Ok(session_token)
            },
            Err(wrapped_error) => {
                if wrapped_error.downcast_ref::<ClientError>().map(|e| e.error_summary.as_ref()) == Some("Authentication failed") {
                    warn!("Authentication failed, re-prompting for Okta credentials");

                    let password = client.prompt_password()?;
                    let login_request = LoginRequest::from_credentials(
                        username.to_owned(),
                        password.clone(),
                    );
                    
                    let session_token = client.get_session_token(&login_request).await?;

                    // Save the password.
                    #[cfg(not(target_os = "linux"))]
                    client.set_cached_password(&keyring, &password);

                    Ok(session_token)
                } else {
                    Err(wrapped_error)
                }
            }
        }?;

        client.new_session(session_token, &HashSet::new()).await?;

        Ok(client)
    }

    pub fn set_session_id(&mut self, session_id: String) {
        self.cookies
            .add_cookie_str(&format!("sid={}", session_id), &self.base_url);
    }

    pub async fn get_response(&self, url: Url) -> Result<Response, Error> {
        self.client
            .get(url)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub async fn get<O>(&self, path: &str) -> Result<O, Error>
    where
        O: DeserializeOwned,
    {
        self.client
            .get(self.base_url.join(path)?)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(|e| e.into())
    }

    pub async fn post<I, O>(&self, path: &str, body: &I) -> Result<O, Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.post_absolute(self.base_url.join(path)?, body).await
    }

    pub async fn post_absolute<I, O>(&self, url: Url, body: &I) -> Result<O, Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        let resp = self
            .client
            .post(url)
            .json(body)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .await?;

        if resp.status().is_success() {
            resp.json().await.map_err(|e| e.into())
        } else {
            Err(resp.json::<ClientError>().await?.into())
        }
    }

    fn prompt_password(&self) -> Result<String, Error> {
        Password::new()
            .with_prompt(&format!("Password for {}", self.base_url))
            .interact()
            .map_err(Into::into)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn get_password(&self, keyring: &Keyring, force_prompt: bool) -> Result<String, Error> {
        // If the user chooses to force new creds, prompt them for them
        if force_prompt {
            self.prompt_password()
        } else {
            match self.get_cached_password(keyring) {
                Some(password) => Ok(password),
                None => self.prompt_password()
            }
        }
    }

    #[cfg(linux)]
    fn can_cache_password(&self) -> bool {
        // We don't support caching passwords on linux,
        // because we cannot guarantee DBus availability
        false
    }

    #[cfg(not(linux))]
    fn can_cache_password(&self) -> bool {
        // Keyring says it supports MacOS and Windows without requirements
        true
    }

    #[cfg(not(target_os = "linux"))]
    fn get_cached_password(&self, keyring: &Keyring) -> Option<String> {
        keyring.get_password().ok()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn set_cached_password(&self, keyring: &Keyring, password: &str) {
        debug!("Saving Okta credentials for {}", self.base_url);
        
        // Don't treat this as a failure, as it is not a hard requirement
        if let Err(e) = keyring.set_password(password) {
            warn!("Error while saving credentials: {}", e);
        }
    }
}
