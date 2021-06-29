use crate::okta::auth::FactorResult;
use crate::okta::auth::LoginResponse;
use crate::okta::client::Client;
use crate::okta::Links;
use crate::okta::Links::Multi;
use crate::okta::Links::Single;

use std::collections::HashMap;
use std::fmt;
use std::thread::sleep;
use std::time::Duration;

use dialoguer::Password;
use failure::Error;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase", tag = "factorType")]
pub enum Factor {
    #[serde(rename_all = "camelCase")]
    Push {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename_all = "camelCase")]
    Sms {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: SmsFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename_all = "camelCase")]
    Call {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: CallFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename = "token", rename_all = "camelCase")]
    Token {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: TokenFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
        verify: Option<FactorVerification>,
    },
    #[serde(rename = "token:software:totp", rename_all = "camelCase")]
    Totp {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: TokenFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename = "token:hardware", rename_all = "camelCase")]
    Hotp {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: TokenFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
        verify: Option<FactorVerification>,
    },
    #[serde(rename_all = "camelCase")]
    Question {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: QuestionFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
    #[serde(rename_all = "camelCase")]
    Web {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: WebFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorProvider {
    Okta,
    Rsa,
    Symantec,
    Google,
    Duo,
    Yubico,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorStatus {
    NotSetup,
    PendingActivation,
    Enrolled,
    Active,
    Inactive,
    Expired,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FactorVerification {
    pass_code: String,
    next_pass_code: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SmsFactorProfile {
    phone_number: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CallFactorProfile {
    phone_number: String,
    phone_extension: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QuestionFactorProfile {
    question: String,
    question_text: String,
    answer: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TokenFactorProfile {
    credential_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WebFactorProfile {
    credential_id: String,
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(untagged)]
pub enum FactorVerificationRequest {
    #[serde(rename_all = "camelCase")]
    Push { state_token: String },
    #[serde(rename_all = "camelCase")]
    Question { answer: String },
    #[serde(rename_all = "camelCase")]
    Sms {
        state_token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pass_code: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Call { pass_code: Option<String> },
    #[serde(rename_all = "camelCase")]
    Totp {
        state_token: String,
        pass_code: String,
    },
    #[serde(rename_all = "camelCase")]
    Token { pass_code: String },
}

impl fmt::Display for Factor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Factor::Push { .. } => write!(f, "Okta Verify Push"),
            Factor::Sms { ref profile, .. } => write!(f, "Okta SMS to {}", profile.phone_number),
            Factor::Call { ref profile, .. } => write!(f, "Okta Call to {}", profile.phone_number),
            Factor::Token { .. } => write!(f, "Okta One-time Password"),
            Factor::Totp { ref provider, .. } => {
                write!(f, "Okta Time-based One-time Password (from {:?})", provider)
            }
            Factor::Hotp { .. } => write!(f, "Okta Hardware One-time Password"),
            Factor::Question { ref profile, .. } => write!(f, "Question: {}", profile.question),
            Factor::Web { .. } => write!(f, "Okta Web"),
        }
    }
}

impl Client {
    pub fn verify(&self, factor: &Factor, state_token: String) -> Result<LoginResponse, Error> {
        match factor {
            Factor::Push { links, .. } => {
                let url = match links.get("verify").unwrap() {
                    Single(ref link) => link.href.clone(),
                    Multi(ref links) => links.first().unwrap().href.clone(),
                };

                let request = FactorVerificationRequest::Push { state_token };

                // Trigger sending of Push
                let mut response: LoginResponse = self.post_absolute(url.clone(), &request)?;

                while Some(FactorResult::Waiting) == response.factor_result {
                    sleep(Duration::from_millis(100));
                    response = self.post_absolute(url.clone(), &request)?;
                }

                match response.factor_result {
                    None | Some(FactorResult::Success) => Ok(response),
                    Some(result) => bail!("Failed to verify with Push MFA ({:?})", result),
                }
            }
            Factor::Sms { links, .. } => {
                let url = match links.get("verify").unwrap() {
                    Single(ref link) => link.href.clone(),
                    Multi(ref links) => links.first().unwrap().href.clone(),
                };

                let request = FactorVerificationRequest::Sms {
                    state_token,
                    pass_code: None,
                };

                // Trigger sending of SMS
                let response: LoginResponse = self.post_absolute(url.clone(), &request)?;

                let state_token = response
                    .state_token
                    .ok_or_else(|| format_err!("No state token found in factor prompt response"))?;

                let request = FactorVerificationRequest::Sms {
                    state_token,
                    pass_code: Some(Password::new().with_prompt(factor.to_string()).interact()?),
                };

                self.post_absolute(url, &request)
            }
            Factor::Totp { links, .. } => {
                let mut url = match links.get("verify").unwrap() {
                    Single(ref link) => link.href.clone(),
                    Multi(ref links) => links.first().unwrap().href.clone(),
                };

                url.set_query(Some("rememberDevice"));

                let request = FactorVerificationRequest::Totp {
                    state_token,
                    pass_code: Password::new().with_prompt(factor.to_string()).interact()?,
                };

                self.post_absolute(url, &request)
            }
            _ => {
                // TODO
                bail!("Unsupported MFA method ({})", factor)
            }
        }
    }
}
