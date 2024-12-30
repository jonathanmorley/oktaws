use crate::okta::client::Client;

use std::collections::HashSet;
use std::fmt;

use eyre::Result;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    session_token: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub login: String,
    pub user_id: String,
    pub expires_at: String,
    pub status: SessionStatus,
    pub last_password_verification: Option<String>,
    pub last_factor_verification: Option<String>,
    pub amr: Vec<AuthenticationMethod>,
    pub mfa_active: bool,
}

#[allow(dead_code)]
#[derive(PartialEq, Eq, Hash)]
pub enum SessionProperties {
    CookieToken,
    CookieTokenUrl,
}

impl fmt::Display for SessionProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CookieToken => write!(f, "cookieToken"),
            Self::CookieTokenUrl => write!(f, "cookieTokenUrl"),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionStatus {
    Active,
    MfaRequired,
    MfaEnroll,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationMethod {
    #[serde(rename = "pwd")]
    PasswordAuthentication,
    #[serde(rename = "swk")]
    ProofOfPossessionOfSoftwareKey,
    #[serde(rename = "hwk")]
    ProofOfPossessionOfHardwareKey,
    #[serde(rename = "otp")]
    OneTimePassword,
    Sms,
    #[serde(rename = "tel")]
    TelephoneCall,
    #[serde(rename = "fpt")]
    Fingerprint,
    #[serde(rename = "kba")]
    KnowledgeBasedAuthentication,
    #[serde(rename = "mfa")]
    MultipleFactorAuthentication,
    #[serde(rename = "mca")]
    MultipleChannelAuthentication,
    #[serde(rename = "sc")]
    SmartCardAuthentication,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityProviderType {
    Okta,
    ActiveDirectory,
    Ldap,
    Federation,
    Social,
}

impl Client {
    /// Create a new Okta session,
    /// and store the session ID on the client
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors during session creation
    pub async fn new_session(
        &mut self,
        session_token: String,
        additional_fields: &HashSet<SessionProperties>,
    ) -> Result<()> {
        let session: Session = self
            .post(
                &format!(
                    "api/v1/sessions?additionalFields={}",
                    additional_fields.iter().join(",")
                ),
                &SessionRequest {
                    session_token: Some(session_token),
                },
            )
            .await?;

        self.set_session_id(&session.id);

        Ok(())
    }
}
