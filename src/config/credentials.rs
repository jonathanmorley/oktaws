use crate::okta::Organization;

use dialoguer::Password;
use failure::{err_msg, Error};
use keyring::Keyring;

pub fn get_password(
    organization: &Organization,
    username: &str,
    force_new: bool,
) -> Result<String, Error> {
    if force_new {
        debug!("Force new is set, prompting for password");
        prompt_password(organization, username)
    } else {
        match Keyring::new(&format!("oktaws::okta::{}", organization.name), username).get_password()
        {
            Ok(password) => Ok(password),
            Err(e) => {
                debug!(
                    "Retrieving cached password failed, prompting for password because of {:?}",
                    e
                );
                prompt_password(organization, username)
            }
        }
    }
}

fn prompt_password(organization: &Organization, username: &str) -> Result<String, Error> {
    let mut url = organization.base_url.clone();
    url.set_username(username)
        .map_err(|_| format_err!("Cannot set username for URL"))?;

    Password::new()
        .with_prompt(&format!("Password for {}", url))
        .interact()
        .map_err(Into::into)
}

pub fn save_credentials(
    organization: &Organization,
    username: &str,
    password: &str,
) -> Result<(), Error> {
    let mut url = organization.base_url.clone();
    url.set_username(username)
        .map_err(|_| err_msg("Cannot set username for URL"))?;

    debug!("Saving Okta credentials for {}", url);

    let service = format!("oktaws::okta::{}", organization.name);
    Keyring::new(&service, username)
        .set_password(password)
        .map_err(|e| format_err!("{}", e))
}
