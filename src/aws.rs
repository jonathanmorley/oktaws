use failure::Error;
use ini::Ini;
use rusoto_core;
use rusoto_core::Region;
use rusoto_sts::{AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Credentials, Sts,
                 StsClient};
use rusoto_credential::StaticProvider;

use std::env;
use std::str;

#[derive(Serialize, Deserialize)]
struct AwsCredentialStore {
    aws_access_key_id: String,
    aws_secret_access_key: String,
    aws_session_token: String,
}

pub fn assume_role(
    principal_arn: &str,
    role_arn: &str,
    saml_assertion: &str,
) -> Result<AssumeRoleWithSAMLResponse, Error> {
    let req = AssumeRoleWithSAMLRequest {
        duration_seconds: None,
        policy: None,
        principal_arn: String::from(principal_arn),
        role_arn: String::from(role_arn),
        saml_assertion: String::from(saml_assertion),
    };

    let provider = StaticProvider::new_minimal(String::from(""), String::from(""));
    let client = StsClient::new(
        rusoto_core::default_tls_client()?,
        provider,
        Region::UsEast1,
    );

    info!("Created client");

    client.assume_role_with_saml(&req).map_err(|e| e.into())
}

pub fn set_credentials(profile: &str, credentials: &Credentials) -> Result<(), Error> {
    let path_buf = env::home_dir().unwrap().join(".aws/credentials");
    let path = path_buf.to_str().unwrap();

    let mut conf = Ini::load_from_file(path)?;

    conf.with_section(Some(profile.to_owned()))
        .set("aws_access_key_id", credentials.access_key_id.to_owned())
        .set(
            "aws_secret_access_key",
            credentials.secret_access_key.to_owned(),
        )
        .set("aws_session_token", credentials.session_token.to_owned());

    info!("Saving AWS credentials to {}", path);
    Ok(conf.write_to_file(path)?)
}
