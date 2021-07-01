use crate::aws::role::Role;

use std::collections::HashSet;
use std::convert::TryFrom;

use failure::Error;
use samuel::assertion::{Assertions, AttributeStatement};
use samuel::response::Response as SamlResponse;

#[derive(Debug)]
pub struct Response {
    pub raw: String,
    pub roles: HashSet<Role>,
}

impl TryFrom<String> for Response {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let decoded_saml = String::from_utf8(base64::decode(&s)?)?;

        trace!("Decoded SAML: {}", decoded_saml);

        let response: SamlResponse = decoded_saml.parse()?;

        let assertions = match response.assertions {
            Assertions::Plaintexts(assertions) => assertions,
            Assertions::Encrypteds(_) => bail!("Encrypted assertions are not currently supported"),
            Assertions::None => bail!("No roles found"),
        };

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
                    .map(|arn| arn.parse())
                    .collect::<Result<HashSet<Role>, Error>>()?,
            })
        } else {
            bail!("No Role Attributes found")
        }
    }
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
