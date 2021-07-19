use failure::Error;
use rusoto_core::{HttpClient, Region};
use rusoto_credential::StaticProvider;
use rusoto_iam::{Iam, IamClient, ListAccountAliasesRequest};

use crate::{aws::role::assume_role, saml::Response};

use self::role::Role;

pub mod credentials;
pub mod role;

pub async fn get_account_alias(role: Role, response: &Response) -> Result<String, Error> {
    let assumption_response = assume_role(role, response.raw.clone(), None)
        .await
        .map_err(|e| format_err!("Error assuming role ({})", e))?;

    let credentials = assumption_response
        .credentials
        .ok_or_else(|| format_err!("No creds"))?;
    let provider = StaticProvider::new(
        credentials.access_key_id,
        credentials.secret_access_key,
        Some(credentials.session_token),
        None,
    );
    let client = IamClient::new_with(HttpClient::new()?, provider, Region::default());

    let mut aliases = client
        .list_account_aliases(ListAccountAliasesRequest {
            marker: None,
            max_items: None,
        })
        .await?;

    match aliases.account_aliases.len() {
        0 => Err(format_err!("No AWS account alias found")),
        1 => Ok(aliases.account_aliases.remove(0)),
        _ => Err(format_err!("More than 1 AWS account alias found")),
    }
}
