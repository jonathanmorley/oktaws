use crate::aws::role::Role;

use std::convert::TryFrom;

use anyhow::{anyhow, Error, Result};
use kuchiki::traits::TendrilSink;
use regex::Regex;
use samuel::assertion::{Assertions, AttributeStatement};
use samuel::response::Response as SamlResponse;
use url::Url;

#[derive(Clone, Debug)]
pub struct Response {
    pub raw: String,
    pub roles: Vec<Role>,
}

impl TryFrom<String> for Response {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let decoded_saml = String::from_utf8(base64::decode(&s)?)?;

        trace!("Decoded SAML: {}", decoded_saml);

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
            Ok(Response {
                raw: s,
                roles: role_attribute
                    .values
                    .into_iter()
                    .map(|arn| {
                        arn.parse()
                            .map_err(|_| anyhow!("Error dyring parsing Role"))
                    })
                    .collect::<Result<Vec<Role>, Error>>()?,
            })
        } else {
            Err(anyhow!("No Role Attributes found"))
        }
    }
}

impl Response {
    pub async fn post_to_aws(&self) -> Result<reqwest::Response> {
        let client = reqwest::Client::new();

        client
            .post(Url::parse("https://signin.aws.amazon.com/saml")?)
            .form(&[
                ("SAMLResponse", &self.raw),
                ("RelayState", &String::from("")),
            ])
            .send()
            .await
            .map_err(Into::into)
    }
}

pub fn extract_account_name(text: &str) -> Result<String> {
    extract_saml_account_name(text).or_else(|_| extract_dashboard_account_name(text))
}

pub fn extract_saml_account_name(text: &str) -> Result<String> {
    let doc = kuchiki::parse_html().one(text);
    let account_str = doc
        .select("div.saml-account-name")
        .map_err(|_| anyhow!("SAML account name Not found"))?
        .next()
        .ok_or_else(|| anyhow!("SAML account name Not found"))?
        .text_contents();

    let re = Regex::new(r"Account: (.+) \(\d+\)").unwrap();
    let caps = re.captures(&account_str).unwrap();

    caps.get(1)
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow!("No account ID found"))
}

pub fn extract_dashboard_account_name(text: &str) -> Result<String> {
    let doc = kuchiki::parse_html().one(text);
    let account_str = doc
        .select("span[data-testid='awsc-nav-account-menu-button']")
        .map_err(|_| anyhow!("Dashboard Account selector not valid"))?
        .next()
        .ok_or_else(|| anyhow!("Dashboard Account name not found in {}", text))?
        .text_contents();

    let re = Regex::new(r"Account: (.+) \(\d+\)").unwrap();
    let caps = re.captures(&account_str).unwrap();

    caps.get(1)
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow!("No account ID found"))
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
