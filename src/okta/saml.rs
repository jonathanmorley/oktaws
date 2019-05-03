use crate::aws::saml::SamlResponse;
use failure::{Compat, Error, Fail};
use kuchiki;
use kuchiki::traits::TendrilSink;
use log_derive::logfn;
use std::str;

#[logfn(Trace)]
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

    saml.parse().map_err(Into::into)
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
