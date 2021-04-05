use crate::okta::Organization;

use dialoguer::{Input, Password};
use failure::Error;
use keyring::Keyring;
#[cfg(windows)]
use rpassword;
use username;

pub fn get_username(org: &Organization) -> Result<String, Error> {
    let mut input = Input::<String>::new();
    input.with_prompt(&format!("Username for {}", org.base_url));
    
    if let Ok(system_user) = username::get_user_name() {
        input.default(system_user);
    }

    input.interact_text().map_err(|e| e.into())
}

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

// We use rpassword here because dialoguer hangs on windows
#[cfg(windows)]
fn prompt_password(organization: &Organization, username: &str) -> Result<String, Error> {
    let mut url = organization.base_url.clone();
    url.set_username(username)
        .map_err(|_| format_err!("Cannot set username for URL"))?;

    rpassword::prompt_password_stdout(&format!("Password for {}: ", url)).map_err(|e| e.into())
}

#[cfg(not(windows))]
fn prompt_password(organization: &Organization, username: &str) -> Result<String, Error> {
    let mut url = organization.base_url.clone();
    url.set_username(username)
        .map_err(|_| format_err!("Cannot set username for URL"))?;

    Password::new().with_prompt(&format!("Password for {}", url))
        .interact()
        .map_err(|e| e.into())
}

pub fn save_credentials(
    organization: &Organization,
    username: &str,
    password: &str,
) -> Result<(), Error> {
    let mut url = organization.base_url.clone();
    url.set_username(username)
        .map_err(|_| format_err!("Cannot set username for URL"))?;

    info!("Saving Okta credentials for {}", url);

    Keyring::new(&format!("oktaws::okta::{}", organization.name), username)
        .set_password(password)
        .map_err(|e| format_err!("{}", e))
}
