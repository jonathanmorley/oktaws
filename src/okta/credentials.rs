use atty::Stream;
use dialoguer::{Input, PasswordInput};
use keyring::Keyring;
#[cfg(windows)]
use rpassword;
use username;
use okra::apis::configuration::Configuration as OktaConfiguration;

use failure::Error;
use log::{debug, info};

pub fn get_username(url: &str) -> Result<String, Error> {
    let mut input = Input::new();
    input.with_prompt(&format!("Username for {}", url));
    if let Ok(system_user) = username::get_user_name() {
        input.default(system_user);
    }

    input.interact().map_err(|e| e.into())
}

pub fn get_password(
    url: &str,
    username: &str
) -> Result<String, Error> {
    let service = format!("oktaws::okta::{}", url);
    match Keyring::new(&service, username).get_password()
        {
            Ok(password) => Ok(password),
            Err(e) => {
                debug!(
                    "Retrieving cached password failed ({:?}). Prompting for password",
                    e
                );
                prompt_password(url, username)
            }
        }
}

// We use rpassword here because dialoguer hangs on windows
#[cfg(windows)]
fn prompt_password(url: &str, username: &str) -> Result<String, Error> {
    rpassword::prompt_password_stdout(&format!("{}'s password for {}: ", username, url)).map_err(|e| e.into())
}

#[cfg(not(windows))]
fn prompt_password(url: &str, username: &str) -> Result<String, Error> {
    if atty::is(Stream::Stdin) {
        PasswordInput::new()
            .with_prompt(&format!("{}'s password for {}", username, url))
            .interact()
            .map_err(|e| e.into())
    } else {
        bail!("Stdin is not a TTY")
    }
}

pub fn save_credentials(configuration: &OktaConfiguration) -> Result<(), Error> {
    let url = configuration.base_path.clone();

    info!("Saving Okta credentials for {}", url);

    let service = format!("oktaws::okta::{}", url);

    let (username, password) = configuration.basic_auth.clone().unwrap();

    Keyring::new(&service, &username)
        .set_password(&password.unwrap())
        .map_err(|e| format_err!("{}", e))
}
