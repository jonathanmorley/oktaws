use crate::okta::client::Client;
use crate::okta::factors::{Factor, FactorResult};

use anyhow::{anyhow, Result};
use dialoguer;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

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
    status: LoginState,
    pub factor_result: Option<FactorResult>,
    #[serde(rename = "_embedded")]
    embedded: Option<LoginEmbedded>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoginEmbedded {
    #[serde(default)]
    factors: Vec<Factor>,
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
    pub async fn login(&self, req: &LoginRequest) -> Result<LoginResponse> {
        let login_type = if req.state_token.is_some() {
            "State Token"
        } else {
            "Credentials"
        };

        debug!("Attempting to login to {} with {login_type}", self.base_url);

        self.post("api/v1/authn", req).await
    }

    pub async fn get_session_token(&self, req: &LoginRequest) -> Result<String> {
        let response = self.login(req).await?;

        trace!("Login response: {:?}", response);

        match response.status {
            LoginState::Success => Ok(response.session_token.unwrap()),
            LoginState::MfaRequired => {
                let factors = response.embedded.unwrap().factors;

                let factor = match factors.len() {
                    0 => Err(anyhow!(
                        "MFA is required, but the user has no enrolled factors"
                    )),
                    1 => {
                        info!(
                            "Only one MFA option is available ({}), using it",
                            factors[0]
                        );
                        Ok(&factors[0])
                    }
                    _ => {
                        let selection = dialoguer::Select::new()
                            .with_prompt("Choose MFA Option")
                            .items(&factors)
                            .default(0)
                            .interact()?;

                        Ok(&factors[selection])
                    }
                }?;

                debug!("Factor: {:?}", factor);

                let state_token = response
                    .state_token
                    .ok_or_else(|| anyhow!("No state token found in response"))?;

                let factor_provided_response = self.verify(factor, state_token).await?;

                trace!("Factor Provided Response: {:?}", factor_provided_response);

                Ok(factor_provided_response.session_token.unwrap())
            }
            _ => Err(anyhow!("Unknown error encountered during login")),
        }
    }
}
