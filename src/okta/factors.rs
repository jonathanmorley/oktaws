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
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorResult {
    Cancelled,
    Challenge,
    Error,
    Failed,
    PasscodeReplayed,
    Rejected,
    Success,
    Timeout,
    TimeWindowExceeded,
    Waiting,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase", tag = "factorType")]
pub enum Factor {
    #[serde(rename_all = "camelCase")]
    Push {
        id: String,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: PushFactorProfile,
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
    #[serde(rename_all = "camelCase")]
    WebAuthn {
        id: String,
        authenticator_name: Option<String>,
        provider: FactorProvider,
        status: Option<FactorStatus>,
        profile: WebAuthnFactorProfile,
        #[serde(rename = "_links")]
        links: HashMap<String, Links>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactorProvider {
    Okta,
    Fido,
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

// https://developer.okta.com/docs/reference/api/factors/#factor-profile-object

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QuestionFactorProfile {
    // answer: Option<String>,
    question: String,
    // question_text: String,
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
    // phone_extension: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PushFactorProfile {
    // credential_id: String,
    // device_type: Option<String>,
    name: Option<String>,
    // platform: Option<String>,
    // version: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TokenFactorProfile {
    // credential_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WebFactorProfile {
    // credential_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnFactorProfile {
    // credential_id: String,
    // app_id: Option<String>,
    // version: Option<String>,
    authenticator_name: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EmailFactorProfile {
    // email: String,
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
    #[serde(rename_all = "camelCase")]
    WebAuthn { state_token: String },
}

impl Factor {
    pub fn is_supported(&self) -> bool {
        match self {
            Self::Hotp { .. } => false,
            Self::Web { .. } => false,
            Self::WebAuthn { .. } => false,
            _ => true
        }
    }
}

impl fmt::Display for Factor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Push {
                provider: FactorProvider::Okta,
                profile:
                    PushFactorProfile {
                        name: Some(ref name),
                        ..
                    },
                ..
            } => write!(f, "Push (to Okta Verify on {name})"),
            Self::Push {
                provider: FactorProvider::Okta,
                ..
            } => write!(f, "Push (to Okta Verify)"),
            Self::Push { ref provider, .. } => write!(f, "Push (to {provider:?})"),
            Self::Sms { ref profile, .. } => write!(f, "SMS (to {})", profile.phone_number),
            Self::Call { ref profile, .. } => write!(f, "Call (to {})", profile.phone_number),
            Self::Token { ref provider, .. } => write!(f, "One-time Password (from {provider:?})"),
            Self::Totp { ref provider, .. } => {
                write!(f, "Time-based One-time Password (from {provider:?})")
            }
            Self::Hotp { ref provider, .. } => {
                write!(f, "Hardware One-time Password (from {provider:?})")
            }
            Self::Question { ref profile, .. } => write!(f, "Question: {}", profile.question),
            Self::Web { ref provider, .. } => write!(f, "Web (from {provider:?})"),
            Self::WebAuthn {
                profile:
                    WebAuthnFactorProfile {
                        authenticator_name: Some(ref authenticator_name),
                        ..
                    },
                ..
            } => write!(f, "Web Authn ({authenticator_name})"),
            Self::WebAuthn { .. } => write!(f, "Web Authn"),
        }
    }
}

impl Client {
    /// Given an MFA factor, follow the verification procedure until the MFA is accepted
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors during validation
    pub async fn verify(&self, factor: &Factor, state_token: String) -> Result<LoginResponse> {
        match factor {
            Factor::Push { links, .. } => {
                let url = links
                    .get("verify")
                    .and_then(|link| match link {
                        Single(ref link) => Some(link.href.clone()),
                        Multi(ref links) => links.first().map(|link| link.href.clone()),
                    })
                    .ok_or_else(|| eyre!("No verify link found"))?;

                let request = FactorVerificationRequest::Push { state_token };

                // Trigger sending of Push
                let mut response: LoginResponse = self.post_absolute(url.clone(), &request).await?;

                while Some(FactorResult::Waiting) == response.factor_result {
                    sleep(Duration::from_millis(100));
                    response = self.post_absolute(url.clone(), &request).await?;
                }

                match response.factor_result {
                    None | Some(FactorResult::Success) => Ok(response),
                    Some(result) => Err(eyre!("Failed to verify with Push MFA ({:?})", result)),
                }
            }
            Factor::Sms { links, .. } => {
                let url = links
                    .get("verify")
                    .and_then(|link| match link {
                        Single(ref link) => Some(link.href.clone()),
                        Multi(ref links) => links.first().map(|link| link.href.clone()),
                    })
                    .ok_or_else(|| eyre!("No verify link found"))?;

                let request = FactorVerificationRequest::Sms {
                    state_token,
                    pass_code: None,
                };

                // Trigger sending of SMS
                let response: LoginResponse = self.post_absolute(url.clone(), &request).await?;

                let state_token = response
                    .state_token
                    .ok_or_else(|| eyre!("No state token found in factor prompt response"))?;

                let request = FactorVerificationRequest::Sms {
                    state_token,
                    pass_code: Some(Password::new().with_prompt(factor.to_string()).interact()?),
                };

                self.post_absolute(url, &request).await
            }
            Factor::Totp { links, .. } => {
                let mut url = links
                    .get("verify")
                    .and_then(|link| match link {
                        Single(ref link) => Some(link.href.clone()),
                        Multi(ref links) => links.first().map(|link| link.href.clone()),
                    })
                    .ok_or_else(|| eyre!("No verify link found"))?;

                url.set_query(Some("rememberDevice"));

                let request = FactorVerificationRequest::Totp {
                    state_token,
                    pass_code: Password::new().with_prompt(factor.to_string()).interact()?,
                };

                self.post_absolute(url, &request).await
            }
            _ => {
                // TODO
                Err(eyre!("Unsupported MFA method ({})", factor))
            }
        }
    }
}
