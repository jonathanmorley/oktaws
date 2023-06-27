#![allow(clippy::module_name_repetitions)]

use std::str;
use std::str::FromStr;

use anyhow::{anyhow, Error, Result};
use aws_arn::ARN;
use aws_sdk_iam::Credentials;
use aws_sdk_sts::Client as StsClient;
use tracing::instrument;

#[derive(Clone, Debug, PartialEq)]
pub struct SamlRole {
    pub provider: ARN,
    pub role: ARN,
}

impl FromStr for SamlRole {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let splitted: Vec<&str> = s.split(',').collect();

        match splitted.len() {
            0 | 1 => Err(anyhow!("Not enough elements in {}", s)),
            2 => Ok(Self {
                provider: splitted[0].parse()?,
                role: splitted[1].parse()?,
            }),
            _ => Err(anyhow!("Too many elements in {}", s)),
        }
    }
}

impl SamlRole {
    /// Parse the role name from the role ARN
    ///
    /// # Errors
    ///
    /// Will return `Err` if the ARN does not have a resource name
    pub fn role_name(&self) -> Result<String> {
        self.role
            .resource
            .path_split()
            .last()
            .ok_or_else(|| anyhow!("No name found in {}", self.role))
            .map(ToString::to_string)
    }

    #[instrument(level = "trace", skip(client))]
    pub async fn assume(
        &self,
        client: StsClient,
        saml_assertion: String,
        duration_seconds: Option<i32>,
    ) -> Result<Credentials, Error> {
        let credentials = client
            .assume_role_with_saml()
            .set_duration_seconds(duration_seconds)
            .principal_arn(self.provider.to_string())
            .role_arn(self.role.to_string())
            .saml_assertion(saml_assertion)
            .send()
            .await?
            .credentials
            .ok_or_else(|| anyhow!("No credentials returned"))?;

        Ok(Credentials::new(
            credentials
                .access_key_id
                .ok_or_else(|| anyhow!("No Access Key Id found"))?,
            credentials
                .secret_access_key
                .ok_or_else(|| anyhow!("No Secret Access Key found"))?,
            credentials.session_token,
            credentials.expiration.map(|dt| dt.try_into().unwrap()),
            "sts",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::aws::saml::Response;

    use std::fs::File;
    use std::io::Read;

    use aws_sdk_sts::{Config as StsConfig, Region as StsRegion};
    use aws_smithy_client::test_connection::TestConnection;
    use aws_smithy_http::body::SdkBody;
    use base64::encode;
    use tokio_test::block_on;

    #[test]
    fn parse_attribute() {
        let attribute =
            "arn:aws:iam::123456789012:saml-provider/okta-idp,arn:aws:iam::123456789012:role/role1";

        let expected_role = SamlRole {
            provider: "arn:aws:iam::123456789012:saml-provider/okta-idp"
                .parse()
                .unwrap(),
            role: "arn:aws:iam::123456789012:role/role1".parse().unwrap(),
        };

        assert_eq!(attribute.parse::<SamlRole>().unwrap(), expected_role);
    }

    #[test]
    fn parse_response() {
        let mut f = File::open("tests/fixtures/saml_response.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: Response = Response::new("https://example.com", saml_base64, None).unwrap();

        let expected_roles = vec![
            SamlRole {
                provider: "arn:aws:iam::123456789012:saml-provider/okta-idp"
                    .parse()
                    .unwrap(),
                role: "arn:aws:iam::123456789012:role/role1".parse().unwrap(),
            },
            SamlRole {
                provider: "arn:aws:iam::123456789012:saml-provider/okta-idp"
                    .parse()
                    .unwrap(),
                role: "arn:aws:iam::123456789012:role/role2".parse().unwrap(),
            },
        ];

        assert_eq!(response.roles().unwrap(), expected_roles);
    }

    #[test]
    fn access_denied() {
        let mut f = File::open("tests/fixtures/access_denied.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let conn = TestConnection::new(vec![(
            http::Request::builder()
                .uri(http::Uri::from_static("https://sts.us-east-1.amazonaws.com/"))
                .body(SdkBody::from(r#"Action=AssumeRoleWithSAML&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fmock-role&PrincipalArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Asaml-provider%2Fokta-idp&SAMLAssertion=SAML_ASSERTION"#)).unwrap(),
            http::Response::builder()
                .status(http::StatusCode::from_u16(403).unwrap())
                .body(saml_xml).unwrap())
        ]);
        let conf = StsConfig::builder()
            .region(StsRegion::new("us-east-1"))
            .build();
        let client = StsClient::from_conf_conn(conf, conn.clone());

        let role = SamlRole {
            provider: "arn:aws:iam::123456789012:saml-provider/okta-idp"
                .parse()
                .unwrap(),
            role: "arn:aws:iam::123456789012:role/mock-role".parse().unwrap(),
        };

        let result =
            block_on(role.assume(client, String::from("SAML_ASSERTION"), None)).unwrap_err();

        assert_eq!(result.to_string(), "Error { code: \"AccessDenied\", message: \"User: null is not authorized to perform: sts:AssumeRoleWithSAML on resource: arn:aws:iam::123456789012:role/mock-role\", request_id: \"b9e07db1-e745-4d0f-be1f-123456789012\" }");

        conn.assert_requests_match(&[]);
    }
}
