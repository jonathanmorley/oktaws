pub mod organization;
pub mod profile;

use std::env::var as env_var;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// Return the location for the Oktaws config directory.
///
/// # Errors
///
/// Will return `Err` if there are no `OKTAWS_HOME` or `HOME`
/// environment variables set.
pub fn oktaws_home() -> Result<PathBuf> {
    match env_var("OKTAWS_HOME") {
        Ok(path) => Ok(PathBuf::from(path)),
        Err(_) => default_profile_location(),
    }
}

/// Return the default location for the Oktaws config directory.
///
/// # Errors
///
/// Will return `Err` if there is no `HOME` environment variable set.
fn default_profile_location() -> Result<PathBuf> {
    match dirs::home_dir() {
        Some(home_dir) => Ok(home_dir.join(".oktaws")),
        None => Err(anyhow!("The environment variable HOME must be set.")),
    }
}
