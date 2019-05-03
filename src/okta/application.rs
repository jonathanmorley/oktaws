use crate::aws::saml::SamlResponse;
use crate::okta::error::OktaError;
use crate::okta::extract_state_token;
use crate::okta::organization::Organization;
use crate::okta::saml;
use crate::okta::saml::ExtractSamlResponseError;
use failure::{bail, format_err, Error};
use log::debug;
use okra::apis::login_api::LoginApi;
use okra::okta::models::AppLink;
use std::borrow::ToOwned;
use std::fmt;

#[derive(Debug)]
pub struct Application {
    pub link: AppLink,
    pub organization: Organization,
}

impl fmt::Display for Application {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.label().unwrap())
    }
}

impl Application {
    pub fn label(&self) -> Result<&str, Error> {
        self.link.label().ok_or_else(|| format_err!("No label"))
    }

    pub fn url(&self) -> Result<&str, Error> {
        self.link.link_url().ok_or_else(|| format_err!("No URL"))
    }

    pub fn saml_response(&mut self) -> Result<SamlResponse, Error> {
        let app_url = self.url()?;

        let response = self.organization.get(app_url)?;

        match saml::extract_saml_response(response.clone()) {
            Err(ExtractSamlResponseError::NotFound) => {
                debug!("No SAML found for {}, will attempt re-login", &self);

                let state_token = extract_state_token(&response)?;
                dbg!(&state_token);

                let new_auth = self.organization.auth_with_state_token(&state_token)?;
                dbg!(&new_auth);

                if let Some(session_token) = new_auth.session_token() {
                    dbg!(&session_token);

                    let response = self
                        .organization
                        .client
                        .login_api()
                        .session_cookie_redirect(true, session_token, app_url)
                        .map_err(|e| format_err!("{:?}", e))?
                        .text()?;

                    match saml::extract_saml_response(response.clone()) {
                        Err(ExtractSamlResponseError::NotFound) => {
                            bail!("Could not find SAML even after MFA")
                        }
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
