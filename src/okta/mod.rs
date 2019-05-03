use failure::{bail, Error};
use regex::Regex;

pub mod application;
pub mod error;
pub mod organization;
pub mod saml;

pub use application::Application;
pub use organization::Organization;

fn extract_state_token(text: &str) -> Result<String, Error> {
    let re = Regex::new(r#"var stateToken = '(.+)';"#)?;

    if let Some(cap) = re.captures(text) {
        Ok(cap[1].to_owned().replace("\\x2D", "-"))
    } else {
        bail!("No state token found")
    }
}
