use crate::okta::client::Client;
use crate::okta::factors::Factor;
use crate::okta::users::User;
use crate::okta::Links;

use dialoguer;
use failure::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<Context>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<Options>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_token: Option<String>,
}

impl LoginRequest {
    pub fn from_credentials(username: String, password: String) -> Self {
        Self {
            audience: None,
            context: None,
            options: None,
            password: Some(password),
            token: None,
            username: Some(username),
            state_token: None,
        }
    }

    pub fn from_state_token(token: String) -> Self {
        Self {
            audience: None,
            context: None,
            options: None,
            password: None,
            token: None,
            username: None,
            state_token: Some(token),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    multi_optional_factor_enroll: bool,
    warn_before_password_expired: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Context {
    device_token: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub state_token: Option<String>,
    pub session_token: Option<String>,
    expires_at: String,
    status: LoginState,
    pub factor_result: Option<FactorResult>,
    relay_state: Option<String>,
    #[serde(rename = "_embedded")]
    embedded: Option<LoginEmbedded>,
    #[serde(rename = "_links", default)]
    links: HashMap<String, Links>,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorResult {
    Waiting,
    Success,
    Rejected,
    Timeout,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginEmbedded {
    #[serde(default)]
    factors: Vec<Factor>,
    user: User,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LoginState {
    Unauthenticated,
    PasswordWarn,
    PasswordExpired,
    Recovery,
    RecoveryChallenge,
    PasswordReset,
    LockedOut,
    MfaEnroll,
    MfaEnrollActivate,
    MfaRequired,
    MfaChallenge,
    Success,
}

impl Client {
    pub fn login(&self, req: &LoginRequest) -> Result<LoginResponse, Error> {
        let login_type = if req.state_token.is_some() {
            "State Token"
        } else {
            "Credentials"
        };

        debug!("Attempting to login with {}", login_type);

        self.post("api/v1/authn", req)
    }

    pub fn get_session_token(&self, req: &LoginRequest) -> Result<String, Error> {
        let response = self.login(req)?;

        trace!("Login response: {:?}", response);

        match response.status {
            LoginState::Success => Ok(response.session_token.unwrap()),
            LoginState::MfaRequired => {
                let factors = response.embedded.unwrap().factors;

                let factor = match factors.len() {
                    0 => bail!("MFA is required, but the user has no enrolled factors"),
                    1 => {
                        info!(
                            "Only one MFA option is available ({}), using it",
                            factors[0]
                        );
                        &factors[0]
                    }
                    _ => {
                        let selection = dialoguer::Select::new()
                            .with_prompt("Choose MFA Option")
                            .items(&factors)
                            .default(0)
                            .interact()?;

                        &factors[selection]
                    }
                };

                debug!("Factor: {:?}", factor);

                let state_token = response
                    .state_token
                    .ok_or_else(|| format_err!("No state token found in response"))?;

                let factor_provided_response = self.verify(&factor, state_token)?;

                trace!("Factor Provided Response: {:?}", factor_provided_response);

                Ok(factor_provided_response.session_token.unwrap())
            }
            _ => {
                bail!("Unknown error encountered during login");
            }
        }
    }
}
