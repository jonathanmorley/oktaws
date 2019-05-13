pub mod credentials;
pub mod saml;

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

#[derive(Clone, Debug, Recap, Deserialize, PartialEq, Eq, Hash)]
#[recap(regex = r#"(?x)
    (?P<provider_arn>[^,]+),(?P<role_arn>[^,]+)"#)]
pub struct RoleProviderPair {
    pub role_arn: String,
    pub provider_arn: String,
}

impl RoleProviderPair {
    pub fn role_name(&self) -> Result<&str, Error> {
        NaiveArn::parse(&self.role_arn)
            .map(|arn| arn.resource.trim_start_matches("role/"))
            .map_err(Into::into)
    }

    pub fn assume_role(self, saml_assertion: String) -> Result<AssumeRoleWithSAMLResponse, Error> {
        let req = AssumeRoleWithSAMLRequest {
            duration_seconds: None,
            policy: None,
            principal_arn: self.provider_arn,
            role_arn: self.role_arn,
            saml_assertion,
        };

        let provider = StaticProvider::new_minimal(String::new(), String::new());
        let client = StsClient::new_with(HttpClient::new()?, provider, Region::default());

        trace!("Assuming role: {:?}", &req);

        client.assume_role_with_saml(req).sync().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attribute() {
        let attribute =
            "arn:aws:iam::123456789012:saml-provider/okta-idp,arn:aws:iam::123456789012:role/role1";

        let expected_role = RoleProviderPair {
            provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
            role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
        };

        assert_eq!(
            attribute.parse::<RoleProviderPair>().unwrap(),
            expected_role
        );
    }

    #[test]
    fn parse_reversed_attribute() {
        let attribute =
            "arn:aws:iam::123456789012:role/role1,arn:aws:iam::123456789012:saml-provider/okta-idp";

        let expected_role = RoleProviderPair {
            provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
            role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
        };

        assert_eq!(
            attribute.parse::<RoleProviderPair>().unwrap(),
            expected_role
        );
    }

    #[test]
    fn role_name() {
        let role = RoleProviderPair {
            provider_arn: String::from("arn:aws:iam::123456789012:saml-provider/okta-idp"),
            role_arn: String::from("arn:aws:iam::123456789012:role/role1"),
        };

        let expected_role_name = "role1";

        assert_eq!(role.role_name().unwrap(), expected_role_name);
    }
}
