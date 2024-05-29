use crate::aws::role::SamlRole;

use std::str::FromStr;

use base64::engine::{general_purpose::STANDARD as b64, Engine};
use eyre::{eyre, Error, Result};
use kuchiki::traits::TendrilSink;
use regex::Regex;
use samuel::assertion::{Assertions, AttributeStatement};
use tracing::error;
use url::Url;

#[derive(Clone, Debug)]
pub struct Response {
    pub url: Url,
    pub saml: String,
    pub relay_state: String,
}

impl Response {
    /// # Errors
    ///
    /// The function will error if the `url` parameter is not a valid URL
    ///
    pub fn new(url: &str, saml: String, relay_state: Option<String>) -> Result<Self> {
        Ok(Self {
            url: Url::from_str(url)?,
            saml,
            relay_state: relay_state.unwrap_or_default(),
        })
    }

    /// # Errors
    ///
    /// The function will error if the `SamlResponse` object is not valid SAML
    ///
    pub fn saml(&self) -> Result<samuel::response::Response> {
        String::from_utf8(b64.decode(&self.saml)?)?
            .parse()
            .map_err(|_| eyre!("Error parsing SAML"))
    }

    /// # Errors
    ///
    /// The function will error if it finds encrypted assertions
    ///
    pub fn roles(&self) -> Result<Vec<SamlRole>> {
        let assertions = match self.saml()?.assertions {
            Assertions::Plaintexts(assertions) => Ok(assertions),
            Assertions::Encrypteds(_) => {
                Err(eyre!("Encrypted assertions are not currently supported"))
            }
            Assertions::None => Ok(vec![]),
        }?;

        let role_attribute = assertions
            .into_iter()
            .flat_map(|assertion| assertion.attribute_statement)
            .flat_map(|attribute| match attribute {
                AttributeStatement::PlaintextAttributes(attributes) => Ok(attributes),
                AttributeStatement::EncryptedAttributes(_) => {
                    Err(error!("Encrypted assertions are not currently supported"))
                }
                AttributeStatement::None => Ok(vec![]),
            })
            .flatten()
            .find(|attribute| attribute.name == "https://aws.amazon.com/SAML/Attributes/Role");

        if let Some(role_attribute) = role_attribute {
            role_attribute
                .values
                .into_iter()
                .map(|arn| arn.parse())
                .collect::<Result<Vec<SamlRole>, Error>>()
        } else {
            Ok(vec![])
        }
    }

    /// Post the SAML document to AWS, imitating the browser-based login flow
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors encountered while sending the request
    pub async fn post(self) -> Result<reqwest::Response> {
        reqwest::Client::new()
            .post(self.url)
            .form(&[
                ("SAMLResponse", self.saml),
                ("RelayState", self.relay_state),
            ])
            .send()
            .await
            .map_err(Into::into)
    }
}

/// Try to parse `text` and extract the AWS account name from it
/// `text` is either:
/// 1. A SAML login screen (if there are multiple roles that the user could choose from)
/// 2. The AWS dashboard (if the user only has a single role to use)
///
/// # Errors
///
/// Will return `Err` if `text` is not valid HTML,
/// or if the AWS account name cannot be found
pub fn extract_account_name(text: &str) -> Result<String> {
    extract_saml_account_name(text).or_else(|_| extract_dashboard_account_name(text))
}

/// Try to parse `text` as a SAML login screen
/// and extract the AWS account name from it
///
/// # Errors
///
/// Will return `Err` if `text` is not valid HTML,
/// or if the AWS account name cannot be found
pub fn extract_saml_account_name(text: &str) -> Result<String> {
    let doc = kuchiki::parse_html().one(text);
    let account_str = doc
        .select("div.saml-account-name")
        .map_err(|()| eyre!("SAML account name Not found"))?
        .next()
        .ok_or_else(|| eyre!("SAML account name Not found"))?
        .text_contents();

    Regex::new(r"Account: (.+) \(\d+\)")?
        .captures(&account_str)
        .ok_or_else(|| eyre!("No account name found"))?
        .get(1)
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| eyre!("No account name found"))
}

/// Try to parse `text` as HTML for the AWS dashboard,
/// and extract the AWS account name from it
///
/// # Errors
///
/// Will return `Err` if `text` is not valid HTML,
/// or if the AWS account name cannot be found
pub fn extract_dashboard_account_name(text: &str) -> Result<String> {
    let doc = kuchiki::parse_html().one(text);
    let account_str = doc
        .select("span[data-testid='awsc-nav-account-menu-button']")
        .map_err(|()| eyre!("Dashboard Account selector not valid"))?
        .next()
        .ok_or_else(|| eyre!("Dashboard Account name not found in {}", text))?
        .text_contents();

    Regex::new(r"Account: (.+) \(\d+\)")?
        .captures(&account_str)
        .ok_or_else(|| eyre!("No account name found"))?
        .get(1)
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| eyre!("No account name found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Read;

    #[test]
    fn parse_response_invalid_no_role() {
        let mut f =
            File::open("tests/fixtures/saml_response_invalid_no_role.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = b64.encode(&saml_xml);

        let response = Response::new("https://example.com", saml_base64, None).unwrap();
        let roles: Error = response.roles().unwrap_err();

        assert_eq!(
            roles.to_string(),
            "Not enough elements in arn:aws:iam::123456789012:saml-provider/okta-idp"
        );
    }
}
