use crate::okta::auth::LoginRequest;
use crate::okta::Organization;

use std::collections::HashSet;
use std::sync::Arc;

use failure::Error;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use reqwest::cookie::Jar;
use reqwest::header::{HeaderValue, ACCEPT};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

pub struct Client {
    client: HttpClient,
    organization: Organization,
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
    pub fn new(
        organization: Organization,
        username: String,
        password: String,
    ) -> Result<Client, Error> {
        let base_url = organization.base_url.clone();
        let jar = Arc::from(Jar::default());

        let mut client = Client {
            client: HttpClient::builder()
                .cookie_store(true)
                .cookie_provider(jar.clone())
                .build()?,
            organization,
            cookies: jar,
        };

        // Visit the homepage to get a DeviceToken (DT) cookie (used for persisting MFA information).
        client.get_response(base_url)?;

        // Do the login
        let session_token =
            client.get_session_token(&LoginRequest::from_credentials(username, password))?;
        client.new_session(session_token, &HashSet::new())?;

        Ok(client)
    }

    pub fn set_session_id(&mut self, session_id: String) {
        self.cookies
            .add_cookie_str(&format!("sid={}", session_id), &self.organization.base_url);
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
            .get(self.organization.base_url.join(path)?)
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
        self.post_absolute(self.organization.base_url.join(path)?, body)
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
}
