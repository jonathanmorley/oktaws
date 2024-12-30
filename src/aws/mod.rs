pub mod profile;
pub mod role;
pub mod saml;
pub mod sso;

use crate::aws::role::SamlRole;
use crate::aws::saml::Response;

use aws_sdk_iam::{Client as IamClient, Config as IamConfig};
use aws_sdk_sts::config::Region as StsRegion;
use aws_sdk_sts::{Client as StsClient, Config as StsConfig};
use eyre::{eyre, Result};

/// Get the AWS account alias via IAM SDK calls
///
/// # Errors
///
/// This will return `Err` if the SAML role cannot be assumed,
/// if the role does not have sufficient permissions to call `list_account_aliases`,
/// or if there are an unexpected number of aliases returned.
pub async fn get_account_alias(role: &SamlRole, response: &Response) -> Result<String> {
    let credentials = role
        .assume(sts_client(), response.saml.clone(), None)
        .await
        .map_err(|e| eyre!("Error assuming role ({})", e))?;

    let config = IamConfig::builder()
        .credentials_provider(credentials)
        .build();

    let mut aliases = IamClient::from_conf(config)
        .list_account_aliases()
        .send()
        .await?
        .account_aliases;
    
    match aliases.len() {
        0 => Err(eyre!("No AWS account alias found")),
        1 => Ok(aliases.remove(0)),
        _ => Err(eyre!("More than 1 AWS account alias found")),
    }
}

#[must_use]
pub fn sts_client() -> StsClient {
    let region = StsRegion::new("us-east-1");
    let config = StsConfig::builder().region(region).build();
    StsClient::from_conf(config)
}
