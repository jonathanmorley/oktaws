pub mod applications;
pub mod auth;
pub mod client;
pub mod factors;
pub mod sessions;

use crate::okta::auth::LoginRequest;
use crate::okta::client::Client;
use crate::saml::Response as SamlResponse;

use std::convert::TryFrom;
use std::str;

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, instrument};
use url::Url;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Links {
    Single(Link),
    Multi(Vec<Link>),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    pub href: Url,
}

impl Client {
    #[async_recursion]
    #[instrument(level = "debug", skip_all, fields(path=app_url.path()))]
    pub async fn get_saml_response(&self, app_url: Url) -> Result<SamlResponse> {
        let response = self.get_response(app_url.clone()).await?.text().await?;

        if is_extra_verification(response.clone())? {
            debug!("No SAML found for app {:?}, will re-login", &app_url);

            let state_token = extract_state_token(&response)?;
            self.get_session_token(&LoginRequest::from_state_token(state_token))
                .await?;
            self.get_saml_response(app_url).await
        } else {
            extract_saml_response(&response).map_err(Into::into)
        }
    }
}

/// Find the JS block setting the state token, and extract the token
///
/// # Errors
///
/// Will return `Err` if the state token cannot be found in `text`
fn extract_state_token(text: &str) -> Result<String> {
    Regex::new(r#"var stateToken = '(.+)';"#)?
        .captures(text)
        .map_or_else(
            || Err(anyhow!("No state token found")),
            |cap| Ok(cap[1].to_owned().replace("\\x2D", "-")),
        )
}

/// Interpret `text` as HTML containing a SAML document,
/// and return that SAML document
///
/// # Errors
///
/// Will return `Err` if the SAML document cannot be found,
/// or if it cannot be parsed as SAML.
pub fn extract_saml_response(text: &str) -> Result<SamlResponse, ExtractSamlResponseError> {
    let doc = kuchiki::parse_html().one(text);
    let input_node = doc
        .select("input[name='SAMLResponse']")
        .map_err(|_| ExtractSamlResponseError::NotFound)?
        .next()
        .ok_or(ExtractSamlResponseError::NotFound)?;

    let attributes = &input_node.attributes.borrow();
    let saml = attributes
        .get("value")
        .ok_or(ExtractSamlResponseError::NotFound)?;

    // trace!("SAML: {}", saml);
    SamlResponse::try_from(saml.to_owned()).map_err(Into::into)
}

/// Check whether the page is asking for extra verification.
/// This is a step during the okta login process that normally results from device tokens
/// not being sent with the request.
///
/// # Errors
///
/// This function should not error
pub fn is_extra_verification(text: String) -> Result<bool> {
    let doc = kuchiki::parse_html().one(text);

    if let Ok(head) = doc.select_first("head") {
        if let Ok(title) = head.as_node().select_first("title") {
            let re = Regex::new(r#".* - Extra Verification$"#)?;

            return Ok(re.is_match(&title.text_contents()));
        }
    }

    Ok(false)
}

#[derive(thiserror::Error, Debug)]
pub enum ExtractSamlResponseError {
    #[error("No SAML found")]
    NotFound,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
