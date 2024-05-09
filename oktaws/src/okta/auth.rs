use crate::okta::client::Client;
use crate::okta::factors::{Factor, FactorResult};

use dialoguer;
use eyre::{eyre, Result};
use kuchiki::traits::TendrilSink;
use regex::Regex;
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
    #[must_use]
    pub const fn from_credentials(username: String, password: String) -> Self {
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

    #[must_use]
    pub const fn from_state_token(token: String) -> Self {
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
    /// Send the login request to Okta.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any issues sending the request
    pub async fn login(&self, req: &LoginRequest) -> Result<LoginResponse> {
        let login_type = if req.state_token.is_some() {
            "State Token"
        } else {
            "Credentials"
        };

        debug!("Attempting to login to {} with {login_type}", self.base_url());

        self.post("api/v1/authn", req).await
    }

    /// Get a session token
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any unrecoverable issues during login,
    /// if there are IO problems while prompting for MFA,
    /// if a state token cannot be found in the response,
    /// or if there are MFA verification errors.
    pub async fn get_session_token(&self, req: &LoginRequest) -> Result<String> {
        let response = self.login(req).await?;

        trace!("Login response: {:?}", response);

        match response.status {
            LoginState::Success => response
                .session_token
                .ok_or_else(|| eyre!("Session token not found")),
            LoginState::MfaRequired => {
                let factors = response
                    .embedded
                    .map(|e| e.factors)
                    .ok_or_else(|| eyre!("MFA required, but no factors found"))?;

                let factor = match factors.len() {
                    0 => Err(eyre!(
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
                    .ok_or_else(|| eyre!("No state token found in response"))?;

                let factor_provided_response = self.verify(factor, state_token).await?;

                trace!("Factor Provided Response: {:?}", factor_provided_response);

                factor_provided_response
                    .session_token
                    .ok_or_else(|| eyre!("Session token not found"))
            }
            _ => Err(eyre!("Unknown error encountered during login")),
        }
    }

    /// Check whether the page is asking for extra verification.
    /// This is a step during the okta login process that normally results from device tokens
    /// not being sent with the request.
    ///
    /// # Errors
    ///
    /// This function should not error
    pub fn extra_verification_token(text: &str) -> Result<Option<String>> {
        let doc = kuchiki::parse_html().one(text.to_string());

        let extra_verification = if let Ok(head) = doc.select_first("head") {
            if let Ok(title) = head.as_node().select_first("title") {
                let re = Regex::new(r#".* - Extra Verification$"#)?;
                re.is_match(&title.text_contents())
            } else {
                false
            }
        } else {
            false
        };

        if extra_verification {
            Regex::new(r#"var stateToken = '(.+)';"#)?
                .captures(text)
                .map_or_else(
                    || Err(eyre!("No state token found")),
                    |cap| Ok(cap[1].to_owned().replace("\\x2D", "-")),
                )
                .map(Option::Some)
        } else {
            Ok(None)
        }
    }
}
