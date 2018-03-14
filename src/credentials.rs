use keyring::Keyring;
use username;
use dialoguer::{Input, PasswordInput};

use failure::Error;

pub fn get_username() -> Result<String, Error> {
    let mut input = Input::new("Okta Username");
    if let Ok(system_user) = username::get_user_name() {
        input.default(&system_user);
    }

    input.interact().map_err(|e| e.into())
}

pub fn get_password(username: &str, force_new: bool) -> Result<String, Error> {
    fn prompt_for_password() -> Result<String, Error> {
        PasswordInput::new("Okta Password")
            .interact()
            .map_err(|e| e.into())
    }

    if force_new {
        debug!("Force new is set, prompting for password");
        prompt_for_password()
    } else {
        match Keyring::new("oktaws::okta", username).get_password() {
            Ok(password) => Ok(password),
            Err(e) => {
                debug!(
                    "Get password failed, prompting for password because of {:?}",
                    e
                );
                prompt_for_password()
            }
        }
    }
}

pub fn set_credentials(username: &str, password: &str) {
    info!("Saving Okta credentials for {}", username);
    let keyring = Keyring::new("oktaws::okta", username);
    trace!("Setting {}'s password to {}", username, password);
    keyring.set_password(password).unwrap();
}
