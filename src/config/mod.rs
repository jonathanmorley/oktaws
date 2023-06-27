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
    env_var("OKTAWS_HOME").map_or_else(
        |_| default_profile_location(),
        |path| Ok(PathBuf::from(path))
    )
}

/// Return the default location for the Oktaws config directory.
///
/// # Errors
///
/// Will return `Err` if there is no `HOME` environment variable set.
fn default_profile_location() -> Result<PathBuf> {
    dirs::home_dir().map_or_else(
        || Err(anyhow!("The environment variable HOME must be set.")),
        |home_dir| Ok(home_dir.join(".oktaws")))
}
