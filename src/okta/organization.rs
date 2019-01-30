use std::fs::File;
use std::io::Read;
use toml;
use try_from::TryFrom;
use crate::okta::credentials;
use okra::apis::configuration::Configuration as OktaConfiguration;
use okra::apis::client::APIClient as OktaClient;
use crate::aws::saml::SamlResponse;
use failure::{Compat, Error};
use kuchiki;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use reqwest::Url;
use serde_str;
use std::str;
use log::{debug, trace, info};
use dirs::home_dir;
use log::error;
use std::env::var as env_var;
use std::path::Path;
use std::path::PathBuf;
use try_from::TryInto;
use walkdir::WalkDir;
use std::ffi::OsStr;
use tokio_core::reactor::Handle;
use futures::future::Future;
use okra::models::{AuthenticationRequest, AuthenticationTransaction, TransactionState, CreateSessionRequest, Session, AuthVerifyFactorRequest};
use crate::okta::saml;
use crate::okta::saml::ExtractSamlResponseError;
use dialoguer::{Input, PasswordInput};

pub struct Organization {
    pub client: OktaClient,
    pub name: String,
    pub username: String,
    pub base_url: String,
    pub profiles: Vec<Profile>,
}

impl Organization {
    pub fn from_file_path<P>(path: &P) -> Result<Organization, Error> where
        P: ?Sized + AsRef<Path>{
        let name = path
            .as_ref()
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .ok_or_else(|| {
                format_err!("Organization name not parseable from {:?}", path.as_ref())
            })?;

        info!("Found Okta organization: {}", name);

        let file_contents = File::open(path)?
            .bytes()
            .map(|b| b.map_err(|e| e.into()))
            .collect::<Result<Vec<u8>, Error>>()?;

        let file_toml: toml::Value = toml::from_slice(&file_contents)?;

        let default_role: Option<String> = file_toml.get("role").and_then(|r| toml_to_string(r));

        let profiles = file_toml
            .get("profiles")
            .and_then(|p| p.as_table())
            .ok_or_else(|| format_err!("No profiles table found"))?
            .into_iter()
            .map(|(k, v)| Profile::from_entry((k.to_owned(), v), default_role.clone()))
            .collect::<Result<Vec<Profile>, Error>>()?;

        let base_url = file_toml.get("url").and_then(|r| toml_to_string(r)).unwrap_or_else(|| format!("https://{}.okta.com", name));

        let username = match file_toml.get("username").and_then(|u| toml_to_string(u)) {
            Some(username) => username,
            None => credentials::get_username(&base_url)?,
        };

        Ok(Organization {
            client: OktaClient::new(OktaConfiguration::new(base_url.clone())),
            name,
            username,
            base_url,
            profiles,
        })
    }

    pub fn store_dt_token(&mut self) -> Result<(), Error> {
        let dt_pattern = Regex::new(r"DT=([^;]+)")?;


        let res = self.client.login_api().login_default().map_err(|e| format_err!("{:?}", e))?;
        let token = res
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|cookie| dt_pattern.captures_iter(cookie))
            .filter_map(|capture| capture.get(1))
            .map(|_match| _match.as_str())
            .next();

        match token {
            Some(token) => {
                let token = token.to_owned();

                let mut configuration = self.client.configuration().to_owned();
                configuration.cookies.insert("DT".into(), token.clone());
                self.client = OktaClient::new(configuration);

                Ok(())
            },
            None => bail!("No DT cookie found")
        }
    }

    pub fn auth_with_credentials(&self) -> Result<AuthenticationTransaction, Error> {
        let password = credentials::get_password(&self.base_url, &self.username)?;

        let auth_request = AuthenticationRequest::new()
            .with_username(self.username.to_owned())
            .with_password(password);

        let transaction = self.client
            .authentication_api()
            .authenticate(auth_request)
            .wait()
            .map_err(|e| format_err!("{:?}", e))?;

        match transaction.status() {
            Some(TransactionState::Success) => Ok(transaction),
            Some(MfaRequired) => self.handle_mfa(&transaction),
            e => bail!("Unsuccessful login with credentials ({:?})", transaction.status())
        }

        //credentials::save_credentials(&organization.okta_configuration)?;
    }

    pub fn auth_with_state_token(&self, state_token: &str) -> Result<AuthenticationTransaction, Error> {
        let auth_request = AuthenticationRequest::new()
            .with_state_token(state_token.to_owned());

        let transaction = self.client
            .authentication_api()
            .authenticate(auth_request)
            .wait()
            .map_err(|e| format_err!("{:?}", e))?;

        match transaction.status() {
            Some(TransactionState::Success) => Ok(transaction),
            Some(MfaRequired) => self.handle_mfa(&transaction),
            e => bail!("Unsuccessful login with state token ({:?})", transaction.status())
        }
    }

    pub fn handle_mfa(&self, transaction: &AuthenticationTransaction) -> Result<AuthenticationTransaction, Error> {
        info!("MFA required");

        let factors = transaction._embedded().unwrap()["factors"].as_array().unwrap().to_owned();

        let factor = match factors.len() {
            0 => bail!("MFA required, and no available factors"),
            1 => {
                info!("Only one factor available, using it");
                &factors[0]
            }
            _ => {
                let mut menu = dialoguer::Select::new();
                for factor in &factors {
                    menu.item(&factor.to_string());
                }
                &factors[menu.interact()?]
            }
        };

        debug!("Factor: {:?}", factor);

        let state_token = transaction
            .state_token()
            .ok_or_else(|| format_err!("No state token found in response"))?.to_owned();

        let factor_prompt_request = AuthVerifyFactorRequest::new().with_state_token(state_token);

        let factor_id = factor.as_object().unwrap()["id"].as_str().unwrap();

        let factor_prompt_response = self.client.authentication_api().auth_verify_factor(factor_id, factor_prompt_request, true, true).wait().map_err(|e| format_err!("{:?}", e))?;

        trace!("Factor Prompt Response: {:?}", factor_prompt_response);
        let mfa_code = Input::new().with_prompt("MFA response").interact()?;

        let state_token = factor_prompt_response
            .state_token()
            .ok_or_else(|| format_err!("No state token found in response"))?.to_owned();

        let factor_provided_request = AuthVerifyFactorRequest::new().with_state_token(state_token).with_pass_code(mfa_code);

        let factor_provided_response = self.client.authentication_api().auth_verify_factor(factor_id, factor_provided_request, true, true).wait().map_err(|e| format_err!("{:?}", e))?;

        trace!("Factor Provided Response: {:?}", factor_provided_response);

        Ok(factor_provided_response)
    }

    pub fn create_session(&mut self, session_token: &str) -> Result<Session, Error> {
        debug!("Creating new session from {}", session_token);
        let session_request = CreateSessionRequest::new().with_session_token(session_token.to_owned());

        // Ensure we remove any old session data first
        let mut configuration = self.client.configuration().to_owned();
        configuration.cookies.remove("sid");
        self.client = OktaClient::new(configuration);

        /*self.client
            .as_configuration_mut()
            .cookies
            .remove("sid");*/

        let session = self.client
            .session_api()
            .create_session(session_request)
            .wait()
            .map_err(|e| format_err!("{:?}", e))?;

        // Create a new OktaClient so that the `sid` cookie gets propogated to all clients
        let mut configuration = self.client.configuration().to_owned();
        configuration.cookies.insert(String::from("sid"), session.id().unwrap().to_string());
        self.client = OktaClient::new(configuration);

        return Ok(session)
    }

    pub fn get(&self, url: &str) -> Result<String, Error> {
        let configuration = self.client.configuration();

        let cookies = configuration
                .cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<String>>()
                .join(";");

        configuration
            .client
            .get(url)
            .header("Cookie", cookies)
            .send()
            .and_then(|mut res| res.text())
            .map_err(|e| e.into())
    }

    pub fn get_response(&self, url: &str) -> Result<reqwest::Response, Error> {
        let configuration = self.client.configuration();

        let cookies = configuration
                .cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<String>>()
                .join(";");

        configuration
            .client
            .get(url)
            .header("Cookie", cookies)
            .send()
            .map_err(|e| e.into())
    }

    pub fn get_saml_response(&mut self, app_url: &str) -> Result<SamlResponse, Error> {
        let response = self.get(app_url)?;

        match saml::extract_saml_response(response.clone()) {
            Err(ExtractSamlResponseError::NotFound) => {
                debug!("No SAML found for app {:?}, will attempt re-login", &app_url);

                let state_token = extract_state_token(&response)?;
                dbg!(&state_token);

                let new_auth = self.auth_with_state_token(&state_token)?;
                dbg!(&new_auth);

                if let Some(session_token) = new_auth.session_token() {
                    dbg!(&session_token);

                    let response = self.client
                        .login_api()
                        .session_cookie_redirect(true, session_token, app_url)
                        .map_err(|e| format_err!("{:?}", e))?
                        .text()?;

                    match saml::extract_saml_response(response.clone()) {
                        Err(ExtractSamlResponseError::NotFound) => bail!("Could not find SAML even after MFA"),
                        Err(e) => Err(e.into()),
                        Ok(saml) => Ok(saml),
                    }
                } else {
                    bail!("No Session Token found in re-login")
                }
            }
            Err(e) => Err(e.into()),
            Ok(saml) => Ok(saml),
        }
    }
}

fn extract_state_token(text: &str) -> Result<String, Error> {
    let re = Regex::new(r#"var stateToken = '(.+)';"#)?;

    if let Some(cap) = re.captures(text) {
        Ok(cap[1].to_owned().replace("\\x2D", "-"))
    } else {
        bail!("No state token found")
    }
}

#[derive(Clone, Debug)]
pub struct Profile {
    pub name: String,
    pub application_name: String,
    pub role: String,
}

impl Profile {
    fn from_entry(
        entry: (String, &toml::value::Value),
        default_role: Option<String>,
    ) -> Result<Profile, Error> {
        let application_name = if entry.1.is_table() {
            entry.1.get("application")
        } else {
            Some(entry.1)
        }
        .and_then(|a| toml_to_string(a))
        .unwrap();

        let role = if entry.1.is_table() {
            entry.1.get("role").and_then(|r| toml_to_string(r))
        } else {
            default_role
        }
        .ok_or_else(|| format_err!("No profile role or default role specified"))?;

        Ok(Profile {
            name: entry.0,
            application_name,
            role,
        })
    }
}

fn toml_to_string(value: &toml::value::Value) -> Option<String> {
    value.as_str().map(|r| r.to_owned())
}
