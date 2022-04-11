pub mod organization;
pub mod profile;

use std::path::PathBuf;
use std::env::var as env_var;

use anyhow::{anyhow, Result};

pub fn oktaws_home() -> Result<PathBuf> {
    match env_var("OKTAWS_HOME") {
        Ok(path) => Ok(PathBuf::from(path)),
        Err(_) => default_profile_location(),
    }
}

fn default_profile_location() -> Result<PathBuf> {
    match dirs::home_dir() {
        Some(home_dir) => Ok(home_dir.join(".oktaws")),
        None => Err(anyhow!("The environment variable HOME must be set.")),
    }
}
