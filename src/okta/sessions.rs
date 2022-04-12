use crate::okta::client::Client;

use std::collections::HashSet;
use std::fmt;

use anyhow::Result;
use itertools::Itertools;
use okta::types::{CreateSessionRequest, SessionAuthenticationMethod, SessionStatus};
use serde::Deserialize;

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
    pub amr: Vec<SessionAuthenticationMethod>,
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
            SessionProperties::CookieToken => write!(f, "cookieToken"),
            SessionProperties::CookieTokenUrl => write!(f, "cookieTokenUrl"),
        }
    }
}

impl Client {
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
                &CreateSessionRequest { session_token },
            )
            .await?;

        self.set_session_id(session.id);

        Ok(())
    }
}
