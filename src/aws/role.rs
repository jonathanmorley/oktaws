use arn::naive::NaiveArn;
use failure::Error;
use log::trace;
use recap::Recap;
use rusoto_core::request::HttpClient;
use rusoto_core::Region;
use rusoto_credential::StaticProvider;
use rusoto_sts::{AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Sts, StsClient};
use serde::Deserialize;
use std::str;

#[derive(Debug, Recap, Deserialize, PartialEq, Eq, Hash)]
#[recap(regex = r#"(?x)(?P<provider_arn>[^,]+),(?P<role_arn>[^,]+)"#)]
pub struct Role {
    pub provider_arn: String,
    pub role_arn: String,
}

impl Role {
    pub fn role_name(&self) -> Result<&str, Error> {
        NaiveArn::parse(&self.role_arn)
            .map(|arn| arn.resource.trim_start_matches("role/"))
            .map_err(Into::into)
    }
}

pub fn assume_role(
    Role {
        provider_arn,
        role_arn,
    }: Role,
    saml_assertion: String,
) -> Result<AssumeRoleWithSAMLResponse, Error> {
    let req = AssumeRoleWithSAMLRequest {
        duration_seconds: None,
        policy: None,
        principal_arn: provider_arn,
        role_arn,
        saml_assertion,
    };

    let provider = StaticProvider::new_minimal(String::new(), String::new());
    let client = StsClient::new_with(HttpClient::new()?, provider, Region::default());

    trace!("Assuming role: {:?}", &req);

    client.assume_role_with_saml(req).sync().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn role_name() {
        let role = Role {
            provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
            role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
        };

        let expected_role_name = "role1";

        assert_eq!(role.role_name().unwrap(), expected_role_name);
    }
}
