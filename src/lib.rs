#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;

mod aws;
mod okta;

use dirs::home_dir;
use failure::Error;
use std::env::var as env_var;
use std::path::PathBuf;

pub fn default_oktaws_location() -> Result<PathBuf, Error> {
    let env = env_var("OKTAWS_CONFIG_DIR").ok().filter(|e| !e.is_empty());
    match env {
        Some(path) => Ok(PathBuf::from(path)),
        None => hardcoded_oktaws_location(),
    }
}

fn hardcoded_oktaws_location() -> Result<PathBuf, Error> {
    match home_dir() {
        Some(mut home_path) => {
            home_path.push(".oktaws");
            Ok(home_path)
        }
        None => bail!("Failed to determine home directory."),
    }
}
