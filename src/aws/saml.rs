use crate::aws::RoleProviderPair;
use failure::{Error, Fail};
use samuel::assertion::{Assertions, AttributeStatement};
use samuel::response::Response;
use std::collections::HashSet;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct SamlResponse {
    pub raw: String,
    pub parsed: Response,
}

impl TryFrom<String> for SamlResponse {
    type Error = ParseSamlResponseError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let decoded = base64::decode(&raw).map_err(ParseSamlResponseError::Base64Decode)?;

        let parsed = String::from_utf8(decoded)
            .map_err(ParseSamlResponseError::Utf8Parse)?
            .parse()
            .map_err(ParseSamlResponseError::SamlParse)?;

        Ok(SamlResponse { raw, parsed })
    }
}

#[derive(Debug, Fail)]
pub enum ParseSamlResponseError {
    #[fail(display = "Could not decode base64 for SAML response: {}", _0)]
    Base64Decode(base64::DecodeError),
    #[fail(display = "SAML Response is not valid utf-8: {}", _0)]
    Utf8Parse(std::string::FromUtf8Error),
    #[fail(display = "SAML Response is not valid SAML: {}", _0)]
    SamlParse(Error),
}

impl SamlResponse {
    pub fn role_provider_pairs(&self) -> Result<Vec<RoleProviderPair>, RolesError> {
        let assertions = match &self.parsed.assertions {
            Assertions::Plaintexts(assertions) => Ok(assertions),
            Assertions::Encrypteds(_) => Err(RolesError::EncryptedAssertions),
            Assertions::None => Err(RolesError::NoAssertions),
        }?;

        let attribute_statements = assertions.iter().flat_map(|a| a.attribute_statement.iter());

        let mut role_provider_pairs = Vec::new();

        for attribute_statement in attribute_statements {
            let attributes = match attribute_statement {
                AttributeStatement::PlaintextAttributes(attributes) => Ok(attributes),
                AttributeStatement::EncryptedAttributes(_) => Err(RolesError::EncryptedAttributes),
                AttributeStatement::None => Err(RolesError::NoAttributes),
            }?;

            let values = attributes
                .iter()
                .filter(|a| a.name == "https://aws.amazon.com/SAML/Attributes/Role")
                .flat_map(|a| a.values.iter())
                .map(|v| v.parse().map_err(RolesError::ParseRole));

            for value in values {
                role_provider_pairs.push(value?)
            }
        }

        Ok(role_provider_pairs)
    }
}

#[derive(Debug, Fail)]
pub enum RolesError {
    #[fail(display = "Encrypted assertion encountered in SAML response: Not supported")]
    EncryptedAssertions,
    #[fail(display = "No assertions found in SAML response")]
    NoAssertions,
    #[fail(display = "Encrypted attribute encountered in SAML response: Not supported")]
    EncryptedAttributes,
    #[fail(display = "No attributes found in SAML response")]
    NoAttributes,
    #[fail(display = "Unable to parse roles from SAML response: {}", _0)]
    ParseRole(recap::Error),
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

        let response = SamlResponse::try_from(saml_base64);

        assert!(response.is_ok());
    }

    #[test]
    fn roles() {
        let mut f = File::open("tests/fixtures/saml/saml_response.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response = SamlResponse::try_from(saml_base64).unwrap();
        let roles = response.role_provider_pairs().unwrap();

        let expected_roles = vec![
            RoleProviderPair {
                provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
                role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
            },
            RoleProviderPair {
                provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
                role_arn: String::from("arn:aws:iam::123456789012:role/role2"),
            },
        ]
        .into_iter()
        .collect::<HashSet<RoleProviderPair>>();

        assert_eq!(roles, expected_roles);
    }

    #[test]
    fn no_roles() {
        let mut f = File::open("tests/fixtures/saml/saml_response_invalid_no_role.xml")
            .expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response = SamlResponse::try_from(saml_base64).unwrap();

        let roles_err = response.role_provider_pairs().unwrap_err();

        assert_eq!(
            roles_err.to_string(),
            "Unable to parse roles from SAML response: No captures resolved in string 'arn:aws:iam::123456789012:saml-provider/okta-idp'"
        );
    }
}
