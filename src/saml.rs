use crate::aws::role::SamlRole;

use std::convert::TryFrom;

use anyhow::{anyhow, Context, Error, Result};
use kuchiki::traits::TendrilSink;
use regex::Regex;
use samuel::assertion::{Assertions, AttributeStatement};
use samuel::response::Response as SamlResponse;
use tracing::error;

#[derive(Clone, Debug)]
pub struct Response {
    pub raw: String,
    pub roles: Vec<SamlRole>,
}

impl TryFrom<String> for Response {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let decoded_saml = String::from_utf8(base64::decode(&s)?)?;

        //trace!("Decoded SAML: {}", decoded_saml);

        let response: SamlResponse = decoded_saml
            .parse()
            .map_err(|_| anyhow!("Error parsing SAML"))?;

        let assertions = match response.assertions {
            Assertions::Plaintexts(assertions) => Ok(assertions),
            Assertions::Encrypteds(_) => {
                Err(anyhow!("Encrypted assertions are not currently supported"))
            }
            Assertions::None => Err(anyhow!("No roles found")),
        }?;

        let role_attribute = assertions
            .into_iter()
            .flat_map(|assertion| assertion.attribute_statement)
            .flat_map(|attribute| match attribute {
                AttributeStatement::PlaintextAttributes(attributes) => attributes,
                AttributeStatement::EncryptedAttributes(_) => {
                    error!("Encrypted assertions are not currently supported");
                    vec![]
                }
                AttributeStatement::None => vec![],
            })
            .find(|attribute| attribute.name == "https://aws.amazon.com/SAML/Attributes/Role");

        if let Some(role_attribute) = role_attribute {
            Ok(Self {
                raw: s,
                roles: role_attribute
                    .values
                    .into_iter()
                    .map(|arn| arn.parse())
                    .collect::<Result<Vec<SamlRole>, Error>>()?,
            })
        } else {
            Err(anyhow!("No Role Attributes found"))
        }
    }
}

impl Response {
    /// Post the SAML document to AWS, imitating the browser-based login flow
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors encountered while sending the request
    pub async fn post_to_aws(&self) -> Result<reqwest::Response> {
        reqwest::Client::new()
            .post("https://signin.aws.amazon.com/saml")
            .form(&[("SAMLResponse", &self.raw), ("RelayState", &String::new())])
            .send()
            .await
            .with_context(|| anyhow!("Roles: {:?}", self.roles))
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
        .map_err(|_| anyhow!("SAML account name Not found"))?
        .next()
        .ok_or_else(|| anyhow!("SAML account name Not found"))?
        .text_contents();

    Regex::new(r"Account: (.+) \(\d+\)")?
        .captures(&account_str)
        .ok_or_else(|| anyhow!("No account name found"))?
        .get(1)
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow!("No account name found"))
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
        .map_err(|_| anyhow!("Dashboard Account selector not valid"))?
        .next()
        .ok_or_else(|| anyhow!("Dashboard Account name not found in {}", text))?
        .text_contents();

    Regex::new(r"Account: (.+) \(\d+\)")?
        .captures(&account_str)
        .ok_or_else(|| anyhow!("No account name found"))?
        .get(1)
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow!("No account name found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Read;

    use base64::encode;

    #[test]
    fn parse_response_invalid_no_role() {
        let mut f =
            File::open("tests/fixtures/saml_response_invalid_no_role.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: Error = Response::try_from(saml_base64).unwrap_err();

        assert_eq!(
            response.to_string(),
            "Not enough elements in arn:aws:iam::123456789012:saml-provider/okta-idp"
        );
    }
}
