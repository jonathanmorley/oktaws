pub mod organization;
pub mod profile;

use crate::config::organization::Organization;

use std::path::Path;
use std::path::PathBuf;
use std::{convert::TryInto, env::var as env_var};

use failure::Error;
use glob::Pattern;
use walkdir::WalkDir;

#[derive(Debug)]
pub struct Config {
    organizations: Vec<Organization>,
}

impl Config {
    pub fn new() -> Result<Config, Error> {
        let oktaws_home = match env_var("OKTAWS_HOME") {
            Ok(path) => PathBuf::from(path),
            Err(_) => default_profile_location()?,
        };

        Ok(Config {
            organizations: organizations_from_dir(&oktaws_home).collect(),
        })
    }

    pub fn organizations(&self, filter: Pattern) -> impl Iterator<Item = &Organization> {
        self.organizations
            .iter()
            .filter(move |&o| filter.matches(&o.name))
    }
}

fn organizations_from_dir(dir: &Path) -> impl Iterator<Item = Organization> {
    WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().try_into())
        .filter_map(|r| match r {
            Ok(organization) => Some(organization),
            Err(e) => {
                error!("{:?}", e);
                None
            }
        })
}

fn default_profile_location() -> Result<PathBuf, Error> {
    match dirs::home_dir() {
        Some(home_dir) => Ok(home_dir.join(".oktaws")),
        None => bail!("The environment variable HOME must be set."),
    }
}
