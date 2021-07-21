use std::str;
use std::str::FromStr;

use anyhow::{Context, Error, Result, anyhow};
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use rusoto_credential::StaticProvider;
use rusoto_sts::{AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Sts, StsClient};
use tracing::instrument;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Role {
    pub provider_arn: String,
    pub role_arn: String,
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let splitted: Vec<&str> = s.split(',').collect();

        match splitted.len() {
            0 | 1 => Err(anyhow!("Not enough elements in {}", s)),
            2 => Ok(Role {
                provider_arn: String::from(splitted[0]),
                role_arn: String::from(splitted[1]),
            }),
            _ => Err(anyhow!("Too many elements in {}", s)),
        }
    }
}

impl Role {
    pub fn role_name(&self) -> Result<&str> {
        let splitted: Vec<&str> = self.role_arn.split('/').collect();

        match splitted.len() {
            0 | 1 => Err(anyhow!("Not enough elements in {}", self.role_arn)),
            2 => Ok(splitted[1]),
            _ => Err(anyhow!("Too many elements in {}", self.role_arn)),
        }
    }
}

#[instrument(level="trace", skip(saml_assertion))]
pub async fn assume_role(
    Role {
        provider_arn,
        role_arn,
    }: &Role,
    saml_assertion: String,
    duration_seconds: Option<i64>,
) -> Result<AssumeRoleWithSAMLResponse, Error> {
    let req = AssumeRoleWithSAMLRequest {
        duration_seconds,
        policy: None,
        principal_arn: provider_arn.to_string(),
        role_arn: role_arn.to_string(),
        saml_assertion,
        policy_arns: None,
    };

    let provider = StaticProvider::new_minimal(String::from(""), String::from(""));
    let client = StsClient::new_with(HttpClient::new()?, provider, Region::default());

    trace!("Assuming role");

    client
        .assume_role_with_saml(req)
        .await
        .with_context(|| anyhow!("Cannot assume role from SAML"))
}

#[cfg(test)]
mod tests {
    use crate::aws::role::Role;
    use crate::saml::Response;

    use std::convert::TryFrom;
    use std::fs::File;
    use std::io::Read;

    use base64::encode;

    #[test]
    fn parse_attribute() {
        let attribute =
            "arn:aws:iam::123456789012:saml-provider/okta-idp,arn:aws:iam::123456789012:role/role1";

        let expected_role = Role {
            provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
            role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
        };

        assert_eq!(attribute.parse::<Role>().unwrap(), expected_role);
    }

    #[test]
    fn parse_response() {
        let mut f = File::open("tests/fixtures/saml_response.xml").expect("file not found");

        let mut saml_xml = String::new();
        f.read_to_string(&mut saml_xml)
            .expect("something went wrong reading the file");

        let saml_base64 = encode(&saml_xml);

        let response: Response = Response::try_from(saml_base64).unwrap();

        let expected_roles = vec![
            Role {
                provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
                role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
            },
            Role {
                provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
                role_arn: String::from("arn:aws:iam::123456789012:role/role2"),
            },
        ];

        assert_eq!(response.roles, expected_roles);
    }
}
