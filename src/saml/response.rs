use failure::{bail, Error};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Response {
    issuer: String,
    signature: Option<Signature>,
    status: Status,
    assertion: Option<Assertion>,
    encrypted_assertion: Option<EncryptedAssertion>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Signature {
    signed_info: SignedInfo,
    signature_value: String,
    key_info: X509KeyInfo,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct SignedInfo {
    canonicalization_method: String,
    signature_method: String,
    reference: Reference,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Reference {
    #[serde(rename = "URI")]
    uri: String,
    transforms: Transforms,
    digest_method: String,
    digest_value: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Transforms {
    #[serde(rename = "Transform")]
    transforms: Vec<Transform>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Transform {
    algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct X509KeyInfo {
    x509_data: X509Data,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct X509Data {
    x509_certificate: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Status {
    status_code: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename = "$value")]
enum StatusCode {
    Success,
    Requester,
    Responder,
    VersionMismatch,
}

impl FromStr for StatusCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:status:Success" => Ok(StatusCode::Success),
            "urn:oasis:names:tc:SAML:2.0:status:Requester" => Ok(StatusCode::Requester),
            "urn:oasis:names:tc:SAML:2.0:status:Responder" => Ok(StatusCode::Responder),
            "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch" => Ok(StatusCode::VersionMismatch),
            e => bail!("{} not recognised as a SAML status code", e),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Assertion {
    issuer: String,
    signature: Option<Signature>,
    subject: Subject,
    conditions: Conditions,
    authn_statement: AuthnStatement,
    attribute_statement: AttributeStatement,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct EncryptedAssertion {
    encrypted_data: EncryptedData,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct EncryptedData {
    encryption_method: String,
    key_info: KeyInfo,
    cipher_data: CipherData,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct KeyInfo {
    encrypted_key: EncryptedKey,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct EncryptedKey {
    encryption_method: String,
    cipher_data: CipherData,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct CipherData {
    cipher_value: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Subject {
    #[serde(rename = "NameID")]
    name_id: String,
    subject_confirmation: SubjectConfirmation,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct SubjectConfirmation {
    method: String,
    subject_confirmation_data: SubjectConfirmationData,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct SubjectConfirmationData {
    not_on_or_after: String,
    recipient: String,
    in_response_to: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Conditions {
    not_before: String,
    not_on_or_after: String,
    audience_restriction: Vec<AudienceRestriction>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct AudienceRestriction {
    audience: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct AuthnStatement {
    authn_instant: String,
    session_not_on_or_after: String,
    session_index: String,
    authn_context: AuthnContext,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct AuthnContext {
    authn_context_class_ref: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct AttributeStatement {
    #[serde(rename = "Attribute")]
    attributes: Vec<Attribute>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Attribute {
    name: String,
    name_format: String,
    #[serde(rename = "AttributeValue")]
    values: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use failure::Error;
    use serde_xml_rs::from_reader;
    use std::fs::File;

    #[test]
    fn parse_response_encrypted_assertion() -> Result<(), Error> {
        let f = File::open("tests/fixtures/saml-responses/saml-response-encrypted-assertion.xml")?;

        let _response: Response = from_reader(f).map_err(|e| {
            println!("{:?}", e);
            format_err!("Unable to parse")
        })?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_assertion_signed_message() -> Result<(), Error> {
        let f = File::open(
            "tests/fixtures/saml-responses/saml-response-signed-assertion-signed-message.xml",
        )?;

        let _response: Response = from_reader(f).map_err(|e| {
            println!("{:?}", e);
            format_err!("Unable to parse")
        })?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_assertion() -> Result<(), Error> {
        let f = File::open("tests/fixtures/saml-responses/saml-response-signed-assertion.xml")?;

        let _response: Response = from_reader(f).map_err(|e| {
            println!("{:?}", e);
            format_err!("Unable to parse")
        })?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_encrypted_assertion() -> Result<(), Error> {
        let f = File::open(
            "tests/fixtures/saml-responses/saml-response-signed-encrypted-assertion.xml",
        )?;

        let _response: Response = from_reader(f).map_err(|e| {
            println!("{:?}", e);
            format_err!("Unable to parse")
        })?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_message_encrypted_assertion() -> Result<(), Error> {
        let f = File::open(
            "tests/fixtures/saml-responses/saml-response-signed-message-encrypted-assertion.xml",
        )?;

        let _response: Response = from_reader(f).map_err(|e| {
            println!("{:?}", e);
            format_err!("Unable to parse")
        })?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_message_signed_encrypted_assertion() -> Result<(), Error> {
        let f = File::open(
            "tests/fixtures/saml-responses/saml-response-signed-message-signed-encrypted-assertion.xml",
        )?;

        let _response: Response = from_reader(f).map_err(|e| {
            println!("{:?}", e);
            format_err!("Unable to parse")
        })?;

        Ok(())
    }

    #[test]
    fn parse_response_signed_message() -> Result<(), Error> {
        let f = File::open("tests/fixtures/saml-responses/saml-response-signed-message.xml")?;

        let _response: Response = from_reader(f).map_err(|e| {
            println!("{:?}", e);
            format_err!("Unable to parse")
        })?;

        Ok(())
    }

    #[test]
    fn parse_response() -> Result<(), Error> {
        let f = File::open("tests/fixtures/saml-responses/saml-response.xml")?;

        let _response: Response = from_reader(f).map_err(|e| {
            println!("{:?}", e);
            format_err!("Unable to parse")
        })?;

        Ok(())
    }
}
