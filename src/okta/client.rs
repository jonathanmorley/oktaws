use crate::okta::Organization;

use std::collections::HashMap;

use failure::Error;
use itertools::Itertools;
use reqwest::header::{HeaderValue, ACCEPT, COOKIE};
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::Response;
use url::Url;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub struct Client {
    client: HttpClient,
    organization: Organization,
    pub cookies: HashMap<String, String>
}

#[derive(Deserialize, Debug, Fail, Serialize)]
#[serde(rename_all = "camelCase")]
#[fail(display = "{}: {}", error_code, error_summary)]
pub struct ClientError {
    error_code: String,
    error_summary: String,
    error_link: String,
    error_id: String,
    error_causes: Option<Vec<ClientErrorSummary>>
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientErrorSummary {
    error_summary: String
}

impl Client {
    pub fn new(organization: Organization) -> Result<Client, Error> {
        let base_url = organization.base_url.clone();
        
        let mut client = Client {
            client: HttpClient::new(),
            organization,
            cookies: HashMap::new()
        };

        let homepage = client.get_response(base_url)?;
        let dt = homepage.cookies().find(|cookie| cookie.name() == "DT").ok_or(format_err!("No DeviceToken cookie sent by Okta"))?;
        client.cookies.insert(String::from("DT"), dt.value().to_string());

        Ok(client)
    }

    pub fn set_session_id(&mut self, session_id: String) {
        self.cookies.insert("sid".to_string(), session_id);
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .join(";")
    }

    pub fn get_response(&self, url: Url) -> Result<Response, Error> {        
        self.client
            .get(url.into_string())
            .header(COOKIE, self.cookie_header())
            .send()?
            .error_for_status()
            .map_err(|e| e.into())
    }

    pub fn get<O>(&self, path: &str) -> Result<O, Error>
    where
        O: DeserializeOwned,
    {
        self.client
            .get(self.organization.base_url.join(path)?.into_string())
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(COOKIE, self.cookie_header())
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
        self.client
            .post(self.organization.base_url.join(path)?.into_string())
            .json(body)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(COOKIE, self.cookie_header())
            .send()?
            .error_for_status()?
            .json()
            .map_err(|e| e.into())
    }

    pub fn post_absolute<I, O>(&self, url: Url, body: &I) -> Result<O, Error>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        let resp = self.client
            .post(url.clone().into_string())
            .json(body)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(COOKIE, self.cookie_header())
            .send()?;

        if resp.status().is_success() {
            resp.json().map_err(|e| e.into())
        } else {
            Err(resp.json::<ClientError>()?.into())
        }
    }
}
