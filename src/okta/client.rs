use crate::okta::auth::LoginRequest;

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use backoff::future::retry;
use backoff::ExponentialBackoff;
use dialoguer::Password;
#[cfg(not(target_os = "linux"))]
use keyring::Keyring;
use reqwest::cookie::Jar;
use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Response;
use reqwest::{Client as HttpClient, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug)]
pub struct Client {
    client: HttpClient,
    pub base_url: Url,
    pub cookies: Arc<Jar>,
}

#[derive(Debug, thiserror::Error)]
pub enum OktaError {
    #[error("Authentication failed")]
    AuthenticationException(String),
    #[error("Too many requests")]
    TooManyRequestsException(String),
    #[error("{0}")]
    Unknown(RawOktaError)
}

impl From<RawOktaError> for OktaError {
    fn from(error: RawOktaError) -> Self {
        match &*error.code {
            "E0000004" => Self::AuthenticationException(error.id),
            "E0000047" => Self::TooManyRequestsException(error.id),
            _ => Self::Unknown(error)
        }
    }
}

#[derive(Deserialize, Debug, thiserror::Error)]
#[error("{code}: {summary}")]
pub struct RawOktaError {
    #[serde(rename = "errorCode")]
    code: String,
    #[serde(rename = "errorLink")]
    link: String,
    #[serde(rename = "errorSummary")]
    summary: String,
    #[serde(rename = "errorId")]
    id: String,
}

impl Client {
    pub async fn new(
        organization: String,
        username: String,
        #[cfg(not(target_os = "linux"))] force_prompt: bool,
    ) -> Result<Self> {
        let mut base_url = Url::parse(&format!("https://{}.okta.com/", organization))?;
        base_url
            .set_username(&username)
            .map_err(|_| anyhow!("Cannot set username for URL"))?;

        let cookies = Arc::from(Jar::default());

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

        #[cfg(not(target_os = "linux"))]
        let service = format!("oktaws::okta::{}", organization);

        #[cfg(not(target_os = "linux"))]
        let keyring = Keyring::new(&service, &username);

        // get password
        #[cfg(not(target_os = "linux"))]
        let password = client.get_password(&keyring, force_prompt)?;
        #[cfg(target_os = "linux")]
        let password = client.prompt_password()?;

        let login_request = LoginRequest::from_credentials(username.to_owned(), password.clone());

        // Do the login
        let session_token = match client.get_session_token(&login_request).await {
            Ok(session_token) => {
                // Save the password.
                #[cfg(not(target_os = "linux"))]
                client.set_cached_password(&keyring, &password);

                Ok(session_token)
            }
            Err(wrapped_error) => {
                if let Some(OktaError::Unknown(okta_error)) = wrapped_error.downcast_ref() {
                    if okta_error.summary == "Authentication failed" {
                        warn!("Authentication failed, re-prompting for Okta credentials");

                        let password = client.prompt_password()?;
                        let login_request =
                            LoginRequest::from_credentials(username.to_owned(), password.clone());

                        let session_token = client.get_session_token(&login_request).await?;

                        // Save the password.
                        #[cfg(not(target_os = "linux"))]
                        client.set_cached_password(&keyring, &password);

                        Ok(session_token)
                    } else {
                        Err(wrapped_error)
                    }
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

    pub async fn get_response(&self, url: Url) -> Result<Response> {
        retry(ExponentialBackoff::default(), || async {
            let resp = self.client.get(url.clone()).send().await?;

            if resp.status() == StatusCode::TOO_MANY_REQUESTS || resp.status().is_server_error() {
                resp.error_for_status().map_err(backoff::Error::Transient)
            } else if resp.status().is_client_error() {
                resp.error_for_status().map_err(backoff::Error::Permanent)
            } else {
                Ok(resp)
            }
        })
        .await
        .map_err(Into::into)
    }

    pub async fn get<O>(&self, path: &str) -> Result<O>
    where
        O: DeserializeOwned,
    {
        let resp = self
            .client
            .get(self.base_url.join(path)?)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .await?;

        if resp.status().is_success() {
            resp.json().await.map_err(Into::into)
        } else {
            let error: OktaError = resp
                .json::<RawOktaError>()
                .await?
                .into();

            Err(error.into())
        }
    }

    pub async fn post<I, O>(&self, path: &str, body: &I) -> Result<O>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.post_absolute(self.base_url.join(path)?, body).await
    }

    pub async fn post_absolute<I, O>(&self, url: Url, body: &I) -> Result<O>
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
            resp.json().await.map_err(Into::into)
        } else {
            Err(resp.json::<RawOktaError>().await?.into())
        }
    }

    fn prompt_password(&self) -> Result<String> {
        Password::new()
            .with_prompt(&format!("Password for {}", self.base_url))
            .interact()
            .map_err(Into::into)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn get_password(&self, keyring: &Keyring, force_prompt: bool) -> Result<String> {
        // If the user chooses to force new creds, prompt them for them
        if force_prompt {
            self.prompt_password()
        } else {
            match self.get_cached_password(keyring) {
                Some(password) => Ok(password),
                None => self.prompt_password(),
            }
        }
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
