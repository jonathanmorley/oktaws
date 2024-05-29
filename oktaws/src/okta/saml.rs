use crate::aws::saml::Response as SamlResponse;
use crate::okta::auth::LoginRequest;
use crate::okta::client::Client;

use std::str;

use async_recursion::async_recursion;
use eyre::{eyre, Result};
use kuchiki::traits::TendrilSink;
use tracing::{debug, instrument};
use url::Url;

impl Client {
    #[async_recursion]
    #[instrument(level = "debug", skip_all, fields(path=app_url.path()))]
    pub async fn get_saml_response(&self, app_url: Url) -> Result<SamlResponse> {
        let response = self.get_response(app_url.clone()).await?.text().await?;

        if let Some(token) = Self::extra_verification_token(&response)? {
            debug!("No SAML found for app {:?}, will re-login", &app_url);

            self.get_session_token(&LoginRequest::from_state_token(token))
                .await?;
            self.get_saml_response(app_url).await
        } else {
            extract_saml_response(&response).map_err(Into::into)
        }
    }
}

/// Interpret `text` as HTML containing a SAML document,
/// and return that SAML document
///
/// # Errors
///
/// Will return `Err` if the SAML document cannot be found,
/// or if it cannot be parsed as SAML.
pub fn extract_saml_response(text: &str) -> Result<SamlResponse> {
    let doc = kuchiki::parse_html().one(text);

    let form = doc
        .select_first("form[id='appForm']")
        .map_err(|()| eyre!("No SAML form found"))?;

    let url = form
        .attributes
        .borrow()
        .get("action")
        .ok_or_else(|| eyre!("No SAML URL found"))?
        .to_owned();
    let saml = form
        .as_node()
        .select_first("input[name='SAMLResponse']")
        .map_err(|()| eyre!("No SAML Response found"))?
        .attributes
        .borrow()
        .get("value")
        .ok_or_else(|| eyre!("No SAML response value found"))?
        .to_owned();
    let relay_state = form
        .as_node()
        .select_first("input[name='RelayState']")
        .ok()
        .and_then(|node| node.attributes.borrow().get("value").map(ToOwned::to_owned));

    SamlResponse::new(&url, saml, relay_state)
}

#[derive(thiserror::Error, Debug)]
pub enum ExtractSamlResponseError {
    #[error("No SAML found")]
    NotFound,
    #[error(transparent)]
    Other(#[from] eyre::Error),
}
