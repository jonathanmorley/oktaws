use crate::okta::auth::LoginRequest;

use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use backoff::future::retry;
use backoff::ExponentialBackoff;
use dialoguer::Password;
use eyre::{eyre, Result};
use reqwest::cookie::Jar;
use reqwest::header::{HeaderValue, ACCEPT};
use reqwest::Response;
use reqwest::{Client as HttpClient, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
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
    Unknown(RawOktaError),
}

impl From<RawOktaError> for OktaError {
    fn from(error: RawOktaError) -> Self {
        match &*error.code {
            "E0000004" => Self::AuthenticationException(error.id),
            "E0000047" => Self::TooManyRequestsException(error.id),
            _ => Self::Unknown(error),
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
    /// Create a new client for an Okta organization
    ///
    /// # Errors
    ///
    /// Will return `Err` if a URL cannot be constructed for the organization,
    /// or if there are underlying HTTP client creation issues.
    pub async fn new(organization: String, username: String, force_prompt: bool) -> Result<Self> {
        let mut base_url = Url::parse(&format!("https://{organization}.okta.com/"))?;
        base_url
            .set_username(&username)
            .map_err(|_| eyre!("Cannot set username for URL"))?;

        let cookies = Arc::from(Jar::default());

        let mut client = Self {
            client: HttpClient::builder()
                .cookie_store(true)
                .cookie_provider(cookies.clone())
                .build()?,
            base_url: base_url.clone(),
            cookies,
        };

        // Visit the homepage to get a DeviceToken (DT) cookie (used for persisting MFA information).
        client.get_response(base_url).await?;

        let service = format!("oktaws::okta::{organization}");
        let keyring = keyring::Entry::new(&service, &username)?;

        // get password
        let password = client.get_password(&keyring, force_prompt)?;
        let login_request = LoginRequest::from_credentials(username.clone(), password.clone());

        // Do the login
        let session_token = match client.get_session_token(&login_request).await {
            Ok(session_token) => {
                // Save the password.
                client.set_cached_password(&keyring, &password);

                Ok(session_token)
            }
            Err(wrapped_error) => {
                if let Some(OktaError::AuthenticationException(_)) = wrapped_error.downcast_ref() {
                    warn!("Authentication failed, re-prompting for Okta credentials");

                    let password = client.prompt_password()?;
                    let login_request =
                        LoginRequest::from_credentials(username.clone(), password.clone());

                    let session_token = client.get_session_token(&login_request).await?;

                    // Save the password.
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

    pub fn set_session_id(&mut self, session_id: &str) {
        self.cookies
            .add_cookie_str(&format!("sid={session_id}"), &self.base_url);
    }

    /// Given an absolute URL (not just a path), perform a GET request against it
    /// This method attempts to retry if the response indicates rate-limiting.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors performing the GET operation.
    pub async fn get_response(&self, url: Url) -> Result<Response> {
        retry(ExponentialBackoff::default(), || async {
            let resp = self.client.get(url.clone()).send().await?;

            if resp.status() == StatusCode::TOO_MANY_REQUESTS || resp.status().is_server_error() {
                resp.error_for_status().map_err(backoff::Error::transient)
            } else if resp.status().is_client_error() {
                resp.error_for_status().map_err(backoff::Error::permanent)
            } else {
                Ok(resp)
            }
        })
        .await
        .map_err(Into::into)
    }

    /// Given a relative path, perform a GET request against it (using the client's base url)
    /// This method attempts to retry if the response indicates rate-limiting.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors performing the GET operation,
    /// or if the output is not JSON-deserializable as type `O`.
    pub async fn get<O>(&self, path: &str) -> Result<O>
    where
        O: DeserializeOwned,
    {
        retry(ExponentialBackoff::default(), || async {
            let url = self
                .base_url
                .join(path)
                .map_err(eyre::Error::from)
                .map_err(backoff::Error::Permanent)?;

            let resp = self
                .client
                .get(url)
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .send()
                .await
                .map_err(eyre::Error::from)
                .map_err(backoff::Error::Permanent)?;

            if resp.status().is_success() {
                resp.json()
                    .await
                    .map_err(eyre::Error::from)
                    .map_err(backoff::Error::Permanent)
            } else {
                let error: OktaError = resp
                    .json::<RawOktaError>()
                    .await
                    .map_err(eyre::Error::from)
                    .map_err(backoff::Error::Permanent)?
                    .into();

                if let OktaError::TooManyRequestsException(_) = error {
                    Err(backoff::Error::transient(eyre::Error::from(error)))
                } else {
                    Err(backoff::Error::permanent(eyre::Error::from(error)))
                }
            }
        })
        .await
    }

    /// Given a relative path, POST the body to it (using the client's base url)
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors performing the POST operation,
    /// or if the output is not JSON-deserializable as type `O`.
    pub async fn post<I, O>(&self, path: &str, body: &I) -> Result<O>
    where
        I: Serialize + Sync,
        O: DeserializeOwned,
    {
        self.post_absolute(self.base_url.join(path)?, body).await
    }

    /// Given an absolute URL (not just a path), POST the body to it.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors performing the POST operation,
    /// or if the output is not JSON-deserializable as type `O`.
    pub async fn post_absolute<I, O>(&self, url: Url, body: &I) -> Result<O>
    where
        I: Serialize + Sync,
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

    fn prompt_password(&self) -> Result<String, io::Error> {
        Password::new()
            .with_prompt(&format!("Password for {}", self.base_url))
            .interact()
    }

    /// Return the password for authenticating with this client
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any IO errors during password prompting,
    /// or if there were errors encountered while retrieving the password from the cache.
    pub fn get_password(&self, keyring: &keyring::Entry, force_prompt: bool) -> Result<String> {
        // If the user chooses to force new creds, prompt them for them
        if force_prompt {
            self.prompt_password().map_err(Into::into)
        } else {
            Self::get_cached_password(keyring)
                .or_else(|_| self.prompt_password().map_err(Into::into))
        }
    }

    fn get_cached_password(keyring: &keyring::Entry) -> Result<String> {
        keyring.get_password().map_err(Into::into)
    }

    pub fn set_cached_password(&self, keyring: &keyring::Entry, password: &str) {
        debug!("Saving Okta credentials for {}", self.base_url);

        // Don't treat this as a failure, as it is not a hard requirement
        if let Err(e) = keyring.set_password(password) {
            warn!("Error while saving credentials: {}", e);
        }
    }
}
