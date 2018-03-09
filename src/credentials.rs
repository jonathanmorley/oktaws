use keyring::Keyring;
use rpassword;
use username;

use std::error::Error;

use std::io::stdout;
use std::io::Write;

pub fn get_username() -> String {
    let system_user = username::get_user_name().unwrap();
    print!("Okta Username [{}]: ", system_user);
    stdout().flush().unwrap();
    let response: String = read!("{}\n");
    match &response as &str {
        "" => system_user,
        response => response.to_owned(),
    }
}

pub fn get_password(username: &str, force_new: bool) -> String {
    fn prompt_for_password() -> String {
        rpassword::prompt_password_stdout("Okta Password: ").unwrap()
    }

    if force_new {
        debug!("Force new is set, prompting for password");
        prompt_for_password()
    } else {
        match Keyring::new("oktaws::okta", &username).get_password() {
            Ok(password) => password,
            Err(e) => {
                debug!(
                    "Get password failed, prompting for password because of {:?}",
                    e.description()
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
