pub mod credentials;
pub mod role;

use crate::aws::role::SamlRole;
use crate::{aws::role::assume_role, saml::Response};

use anyhow::{anyhow, Result};
use aws_sdk_iam::{Client as IamClient, Config as IamConfig};

pub async fn get_account_alias(role: &SamlRole, response: &Response) -> Result<String> {
    let credentials = assume_role(role, response.raw.clone(), None)
        .await
        .map_err(|e| anyhow!("Error assuming role ({})", e))?;

    let config = IamConfig::builder()
        .credentials_provider(credentials)
        .build();

    let client = IamClient::from_conf(config);

    let mut aliases = client
        .list_account_aliases()
        .send()
        .await?
        .account_aliases
        .unwrap();

    match aliases.len() {
        0 => Err(anyhow!("No AWS account alias found")),
        1 => Ok(aliases.remove(0)),
        _ => Err(anyhow!("More than 1 AWS account alias found")),
    }
}
