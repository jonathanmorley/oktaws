use crate::okta::application::Application;
use atty::Stream;
use dialoguer::{Input, PasswordInput};
use failure::{bail, format_err, Error};
use keyring::Keyring;
use log::{debug, info, trace, warn};
use log_derive::{logfn, logfn_inputs};
use okra::apis::client::APIClient as OktaClient;
use okra::apis::login_api::LoginApi;
use okra::okta::apis::configuration::Configuration as OktaConfiguration;
use okra::okta::models::{
    AuthVerifyFactorRequest, AuthenticationRequest, AuthenticationTransaction,
    CreateSessionRequest, Session, TransactionState,
};
#[cfg(windows)]
use rpassword;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str;

pub struct Organization {
    pub client: OktaClient,
    pub username: String,
    pub base_url: String,
}

impl fmt::Debug for Organization {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Organization {{ username: {}, base_url: {} }}",
            self.username, self.base_url
        )
    }
}

impl fmt::Display for Organization {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.base_url)
    }
}

impl Clone for Organization {
    fn clone(&self) -> Self {
        Organization {
            client: OktaClient::new(self.client.configuration().to_owned()),
            username: self.username.clone(),
            base_url: self.base_url.clone(),
        }
    }
}

impl Organization {
    pub fn new(base_url: String, username: String) -> Self {
        Organization {
            client: OktaClient::new(OktaConfiguration::new(base_url.clone())),
            username,
            base_url,
        }
    }

    // Credentials

    fn get_password(&self) -> Result<String, Error> {
        let service = format!("oktaws::okta::{}", self.base_url);
        Keyring::new(&service, &self.username)
            .get_password()
            .or_else(|e| {
                debug!("Retrieving cached password failed. {:?}", e);
                self.prompt_password()
            })
    }

    // We use rpassword here because dialoguer hangs on windows
    #[cfg(windows)]
    fn prompt_password(&self) -> Result<String, Error> {
        rpassword::prompt_password_stdout(&format!(
            "{}'s password for {}: ",
            self.username, self.base_url
        ))
        .map_err(Into::into)
    }

    #[cfg(not(windows))]
    fn prompt_password(&self) -> Result<String, Error> {
        if atty::is(Stream::Stdin) {
            PasswordInput::new()
                .with_prompt(&format!(
                    "{}'s password for {}",
                    self.username, self.base_url
                ))
                .interact()
                .map_err(Into::into)
        } else {
            bail!("Stdin is not a TTY")
        }
    }

    fn save_credentials(&self, password: &str) -> Result<(), Error> {
        debug!("saving Okta credentials for {}", self);

        let service = format!("oktaws::okta::{}", self.base_url);

        Keyring::new(&service, &self.username)
            .set_password(&password)
            .map_err(|e| format_err!("{}", e))
    }

    // Authentication

    fn auth_with_password(&self, password: String) -> Result<AuthenticationTransaction, Error> {
        let auth_request = AuthenticationRequest::new()
            .with_username(self.username.to_owned())
            .with_password(password.clone());

        if let Ok(transaction) = self.client.authentication_api().authenticate(auth_request) {
            self.save_credentials(&password)?;

            match transaction.status() {
                Some(TransactionState::Success) => Ok(transaction),
                Some(TransactionState::MfaRequired) => self.handle_mfa(&transaction),
                e => bail!("Unexpected transaction state {:?}", e),
            }
        } else {
            warn!("Unsuccessful login with credentials");
            self.auth_with_password(self.prompt_password()?)
        }
    }

    pub fn auth_with_credentials(&self) -> Result<AuthenticationTransaction, Error> {
        self.auth_with_password(self.get_password()?)
    }

    pub fn auth_with_state_token(
        &self,
        state_token: &str,
    ) -> Result<AuthenticationTransaction, Error> {
        let auth_request = AuthenticationRequest::new().with_state_token(state_token.to_owned());

        let transaction = self
            .client
            .authentication_api()
            .authenticate(auth_request)?;

        match transaction.status() {
            Some(TransactionState::Success) => Ok(transaction),
            Some(TransactionState::MfaRequired) => self.handle_mfa(&transaction),
            e => bail!("Unsuccessful transaction state {:?}", e),
        }
    }

    #[logfn(Trace)]
    pub fn handle_mfa(
        &self,
        transaction: &AuthenticationTransaction,
    ) -> Result<AuthenticationTransaction, Error> {
        info!("MFA required");

        let factors = transaction.r#embedded().unwrap()["factors"]
            .as_array()
            .unwrap()
            .to_owned();

        let factor = match factors.len() {
            0 => bail!("MFA required, and no available factors"),
            1 => {
                info!("only one factor available, using it");
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
            .ok_or_else(|| format_err!("No state token found in response"))?
            .to_owned();

        let factor_prompt_request = AuthVerifyFactorRequest::new().with_state_token(state_token);

        let factor_id = factor.as_object().unwrap()["id"].as_str().unwrap();

        let factor_prompt_response = self.client.authentication_api().auth_verify_factor(
            factor_id.to_string(),
            true,
            true,
            AuthVerifyFactorRequest::default(),
        )?;

        trace!("Factor Prompt Response: {:?}", factor_prompt_response);
        let mfa_code = Input::new().with_prompt("MFA response").interact()?;

        let state_token = factor_prompt_response
            .state_token()
            .ok_or_else(|| format_err!("No state token found in response"))?
            .to_owned();

        let _factor_provided_request = AuthVerifyFactorRequest::new()
            .with_state_token(state_token)
            .with_pass_code(mfa_code);

        let factor_provided_response = self.client.authentication_api().auth_verify_factor(
            factor_id.to_string(),
            true,
            true,
            AuthVerifyFactorRequest::default(),
        )?;

        Ok(factor_provided_response)
    }

    // Sessions

    #[logfn_inputs(Debug, fmt = "authenticating against {}")]
    pub fn with_session(self) -> Result<Self, Error> {
        self.clone().with_ui_session(UISession::try_from(self)?)
    }

    #[logfn(Trace)]
    pub fn get_dt_token(&self) -> Result<String, Error> {
        self.client
            .login_api()
            .login_default()
            .map_err(|e| format_err!("{:?}", e))?
            .cookies()
            .find(|cookie| cookie.name() == "DT")
            .map(|cookie| cookie.value().to_owned())
            .ok_or_else(|| format_err!("No DT cookie found"))
    }

    pub fn with_ui_session(mut self, ui_session: UISession) -> Result<Self, Error> {
        let cookies: HashMap<String, String> = ui_session.into();

        let mut configuration = self.client.configuration().to_owned();
        configuration.cookies.extend(cookies.into_iter());

        self.client = OktaClient::new(configuration);

        Ok(self)
    }

    pub fn convert_session(&self, session_token: &str) -> Result<Session, Error> {
        let req = CreateSessionRequest::new().with_session_token(String::from(session_token));

        // Run this against a client with no sid
        let mut configuration = self.client.configuration().to_owned();
        configuration.cookies.remove("sid");

        let temp_client = OktaClient::new(configuration);
        temp_client.session_api().create_session(req)
    }

    // HTTP Client

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
            .map_err(Into::into)
    }

    pub fn into_applications(self) -> Result<impl Iterator<Item = Application>, Error> {
        Ok(self
            .client
            .user_api()
            .list_app_links(String::from("me"), true)?
            .into_iter()
            .map(move |link| Application {
                link,
                organization: self.clone(),
            }))
    }

    pub fn into_aws_applications(self) -> Result<impl Iterator<Item = Application>, Error> {
        self.into_applications()
            .map(|a| a.filter(|app| app.link.app_name() == Some("amazon_aws")))
    }

    pub fn into_application(self, app_label: &str) -> Result<Application, Error> {
        let err_msg = format_err!("could not find application {} in {}", app_label, &self);

        self.into_applications()?
            .find(|app| app.link.label() == Some(app_label))
            .ok_or(err_msg)
    }
}

pub struct UISession {
    dt_token: String,
    session: Session,
}

impl From<UISession> for HashMap<String, String> {
    fn from(value: UISession) -> Self {
        let mut cookies = HashMap::new();
        cookies.insert("DT".to_string(), value.dt_token);
        cookies.insert("sid".to_string(), value.session.id().unwrap().to_string());

        cookies
    }
}

impl TryFrom<Organization> for UISession {
    type Error = failure::Error;

    fn try_from(org: Organization) -> Result<Self, Self::Error> {
        let auth_transaction = org.auth_with_credentials()?;
        if let Some(session_token) = auth_transaction.session_token() {
            Ok(UISession {
                dt_token: org.get_dt_token()?,
                session: org.convert_session(session_token)?,
            })
        } else {
            bail!("No session token found")
        }
    }
}
