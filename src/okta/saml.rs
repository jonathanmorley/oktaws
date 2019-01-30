use crate::aws::saml::SamlResponse;
use failure::{Compat, Error};
use kuchiki;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use reqwest::Url;
use serde_str;
use std::str;
use log::{debug, trace};
use okra::apis::client::APIClient;
use crate::okta::organization::Organization;
use dirs::home_dir;
use log::error;
use std::env::var as env_var;
use std::path::Path;
use std::path::PathBuf;
use try_from::TryInto;
use walkdir::WalkDir;
use std::ffi::OsStr;
use tokio_core::reactor::Handle;

pub fn extract_saml_response(text: String) -> Result<SamlResponse, ExtractSamlResponseError> {
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
    saml.parse().map_err(|e: Error| e.into())
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
