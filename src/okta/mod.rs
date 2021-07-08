pub mod auth;
pub mod client;
pub mod factors;
pub mod sessions;
pub mod users;

use crate::okta::auth::LoginRequest;
use crate::okta::client::Client;
use crate::saml::Response as SamlResponse;

use std::convert::TryFrom;
use std::str;

use async_recursion::async_recursion;
use failure::{Compat, Error};
use kuchiki::traits::TendrilSink;
use regex::Regex;
use serde::Deserialize;
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
    name: Option<String>,
    pub href: Url,
    hints: Hint,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    allow: Vec<String>,
}

impl Client {
    // #[async_recursion]
    // pub async fn get_account_name(&self, app_url: Url) -> Result<String, Error> {
    //     let response = self.get_response(app_url.clone()).await?.text().await?;

    //     trace!("SAML response doc for app {:?}: {}", &app_url, &response);

    //     if is_extra_verification(response.clone()) {
    //         debug!("No SAML found for app {:?}, will re-login", &app_url);

    //         let state_token = extract_state_token(&response)?;
    //         self.get_session_token(&LoginRequest::from_state_token(state_token))
    //             .await?;
    //         self.get_account_name(app_url).await
    //     } else {
    //         extract_account_name(&response).map_err(|e| e.into())
    //     }
    // }

    #[async_recursion]
    pub async fn get_saml_response(&self, app_url: Url) -> Result<SamlResponse, Error> {
        let response = self.get_response(app_url.clone()).await?.text().await?;

        trace!("SAML response doc for app {:?}: {}", &app_url, &response);

        if is_extra_verification(response.clone()) {
            debug!("No SAML found for app {:?}, will re-login", &app_url);

            let state_token = extract_state_token(&response)?;
            self.get_session_token(&LoginRequest::from_state_token(state_token))
                .await?;
            self.get_saml_response(app_url).await
        } else {
            extract_saml_response(&response).map_err(|e| e.into())
        }
    }
}

fn extract_state_token(text: &str) -> Result<String, Error> {
    let re = Regex::new(r#"var stateToken = '(.+)';"#)?;

    if let Some(cap) = re.captures(text) {
        Ok(cap[1].to_owned().replace("\\x2D", "-"))
    } else {
        bail!("No state token found")
    }
}

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

    trace!("SAML: {}", saml);
    SamlResponse::try_from(saml.to_owned()).map_err(Into::into)
}

// pub fn extract_account_name(text: &str) -> Result<String, Error> {
//     let doc = kuchiki::parse_html().one(text);
//     let account_str = doc
//         .select("div.saml-account-name")
//         .map_err(|_| format_err!("Not found"))?
//         .next()
//         .ok_or_else(|| format_err!("Not found"))?;

//     trace!("SAML: {:?}", account_str);

//     Ok(account_str.text_contents())
// }

pub fn is_extra_verification(text: String) -> bool {
    let doc = kuchiki::parse_html().one(text);

    if let Ok(head) = doc.select_first("head") {
        if let Ok(title) = head.as_node().select_first("title") {
            let re = Regex::new(r#".* - Extra Verification$"#).unwrap();

            return re.is_match(&title.text_contents());
        }
    }

    false
}

#[derive(Fail, Debug)]
pub enum ExtractSamlResponseError {
    #[fail(display = "No SAML found")]
    NotFound,
    #[fail(display = "{}", _0)]
    Invalid(#[cause] Compat<Error>),
}

impl From<Error> for ExtractSamlResponseError {
    fn from(e: Error) -> ExtractSamlResponseError {
        ExtractSamlResponseError::Invalid(e.compat())
    }
}
