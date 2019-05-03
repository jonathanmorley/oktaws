use crate::aws::role::Role;
use failure::{bail, Error};
use log::trace;
use samuel::assertion::{Assertions, AttributeStatement};
use samuel::response::Response;
use std::collections::HashSet;
use std::str::FromStr;

#[derive(Debug)]
pub struct SamlResponse {
    pub raw: String,
    pub roles: HashSet<Role>,
}

impl FromStr for SamlResponse {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded_saml = String::from_utf8(base64::decode(&s)?)?;

        trace!("SAML XML Response: {}", decoded_saml);

        let response: Response = decoded_saml.parse()?;

        let mut roles = HashSet::new();

        let assertions = match response.assertions {
            Assertions::Plaintexts(assertions) => assertions,
            Assertions::Encrypteds(_) => bail!("Encrypted assertions not supported"),
            Assertions::None => bail!("No assertions found"),
        };

        let attribute_statements = assertions.into_iter().flat_map(|a| a.attribute_statement);

        for attribute_statement in attribute_statements {
            let attributes = match attribute_statement {
                AttributeStatement::PlaintextAttributes(attributes) => attributes,
                AttributeStatement::EncryptedAttributes(_) => {
                    bail!("Encrypted attributes not supported")
                }
                AttributeStatement::None => bail!("No attributes found"),
            };

            let values = attributes
                .into_iter()
                .filter(|a| a.name == "https://aws.amazon.com/SAML/Attributes/Role")
                .flat_map(|a| a.values)
                .map(|v| v.parse());

            for value in values {
                roles.insert(value?);
            }
        }

        Ok(SamlResponse {
            raw: s.to_owned(),
            roles,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::encode;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn parse_response() {
        let mut f = File::open("tests/fixtures/saml/saml_response.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: SamlResponse = saml_base64.parse().unwrap();

        let expected_roles = vec![
            Role {
                provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
                role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
            },
            Role {
                provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
                role_arn: String::from("arn:aws:iam::123456789012:role/role2"),
            },
        ]
        .into_iter()
        .collect::<HashSet<Role>>();

        assert_eq!(response.roles, expected_roles);
    }

    #[test]
    fn parse_response_invalid_no_role() {
        let mut f = File::open("tests/fixtures/saml/saml_response_invalid_no_role.xml")
            .expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: Error = saml_base64.parse::<SamlResponse>().unwrap_err();

        assert_eq!(
            response.to_string(),
            "No captures resolved in string 'arn:aws:iam::123456789012:saml-provider/okta-idp'"
        );
    }
}
