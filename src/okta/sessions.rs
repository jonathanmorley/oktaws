use crate::okta::client::Client;

use std::collections::HashSet;
use std::fmt;

use failure::Error;
use serde::{Deserialize, Serialize};
use itertools::Itertools;

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
    pub idp: IdentityProvider,
    pub mfa_active: bool
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
            SessionProperties::CookieToken => write!(f, "cookieToken"),
            SessionProperties::CookieTokenUrl => write!(f, "cookieTokenUrl"),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionStatus {
    Active,
    MfaRequired,
    MfaEnroll
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
    #[serde(rename = "sms")]
    Geolocation,
    #[serde(rename = "fpt")]
    Fingerprint,
    #[serde(rename = "kba")]
    KnowledgeBasedAuthentication,
    #[serde(rename = "mfa")]
    MultipleFactorAuthentication,
    #[serde(rename = "mca")]
    MultipleChannelAuthentication,
    #[serde(rename = "sc")]
    SmartCardAuthentication
}

#[derive(Deserialize, Debug)]
pub struct IdentityProvider {
    id: String,
    r#type: IdentityProviderType
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityProviderType {
    Okta,
    ActiveDirectory,
    Ldap,
    Federation,
    Social
}

impl Client {
    pub fn new_session(
        &mut self,
        session_token: String,
        additional_fields: &HashSet<SessionProperties>,
    ) -> Result<(), Error> {
        let session: Session = self.post(
            &format!(
                "api/v1/sessions?additionalFields={}",
                additional_fields.iter().join(",")
            ),
            &SessionRequest {
                session_token: Some(session_token),
            },
        )?;

        self.set_session_id(session.id);

        Ok(())
    }
}
