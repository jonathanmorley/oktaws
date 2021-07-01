use crate::okta::auth::LoginRequest;

use std::collections::HashSet;
use std::sync::Arc;

use dialoguer::Password;
use failure::Error;
use keyring::Keyring;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use reqwest::cookie::Jar;
use reqwest::header::{HeaderValue, ACCEPT};
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
    pub fn new(organization: String, username: String, force_prompt: bool) -> Result<Self, Error> {
        let mut base_url = Url::parse(&format!("https://{}.okta.com/", organization))?;
        base_url
            .set_username(&username)
            .map_err(|_| format_err!("Cannot set username for URL"))?;

        let cookies = Arc::from(Jar::default());

        let service = format!("oktaws::okta::{}", organization);
        let keyring = Keyring::new(&service, &username);

        let mut client = Client {
            client: HttpClient::builder()
                .cookie_store(true)
                .cookie_provider(cookies.clone())
                .build()?,
            base_url: base_url.clone(),
            cookies,
        };

        // Visit the homepage to get a DeviceToken (DT) cookie (used for persisting MFA information).
        client.get_response(base_url)?;

        // get password
        let password = if force_prompt {
            debug!("Force new is set, prompting for password");
            client.prompt_password()
        } else {
            client.get_password(&keyring)
        }?;

        // Do the login
        let session_token = client.get_session_token(&LoginRequest::from_credentials(
            username.to_owned(),
            password.clone(),
        ))?;
        client.new_session(session_token, &HashSet::new())?;

        // Save the password. Don't treat this as a failure, as it is not a hard requirement
        if let Err(e) = client.save_password(&keyring, &password) {
            warn!("Error while saving credentials: {}", e);
        }

        Ok(client)
    }

    pub fn set_session_id(&mut self, session_id: String) {
        self.cookies
            .add_cookie_str(&format!("sid={}", session_id), &self.base_url);
    }

    pub fn get_response(&self, url: Url) -> Result<Response, Error> {
        self.client
            .get(url)
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn get<O>(&self, path: &str) -> Result<O, Error>
    where
        O: DeserializeOwned,
    {
        self.client
            .get(self.base_url.join(path)?)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }

    pub fn post<I, O>(&self, path: &str, body: &I) -> Result<O, Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        self.post_absolute(self.base_url.join(path)?, body)
    }

    pub fn post_absolute<I, O>(&self, url: Url, body: &I) -> Result<O, Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        let resp = self
            .client
            .post(url)
            .json(body)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()?;

        if resp.status().is_success() {
            resp.json().map_err(|e| e.into())
        } else {
            Err(resp.json::<ClientError>()?.into())
        }
    }

    fn prompt_password(&self) -> Result<String, Error> {
        Password::new()
            .with_prompt(&format!("Password for {}", self.base_url))
            .interact()
            .map_err(Into::into)
    }

    pub fn get_password(&self, keyring: &Keyring) -> Result<String, Error> {
        keyring.get_password().or_else(|e| {
            debug!(
                "Retrieving cached password failed, prompting for password because of {:?}",
                e
            );
            self.prompt_password()
        })
    }

    pub fn save_password(&self, keyring: &Keyring, password: &str) -> Result<(), Error> {
        debug!("Saving Okta credentials for {}", self.base_url);
        keyring
            .set_password(password)
            .map_err(|e| format_err!("{}", e))
    }
}
