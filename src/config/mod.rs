pub mod credentials;
pub mod organization;

use config::organization::Organization;
use dirs::home_dir;
use failure::Error;
use std::env::var as env_var;
use std::path::Path;
use std::path::PathBuf;
use try_from::TryInto;
use walkdir::WalkDir;

#[derive(Debug)]
pub struct Config {
    organizations: Vec<Organization>,
}

impl Config {
    pub fn new() -> Result<Config, Error> {
        Ok(Config {
            organizations: organizations_from_dir(&default_oktaws_location()?).collect(),
        })
    }

    pub fn organizations(self) -> impl Iterator<Item = Organization> {
        self.organizations.into_iter()
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

pub fn default_oktaws_location() -> Result<PathBuf, Error> {
    let env = env_var("OKTAWS_HOME").ok().filter(|e| !e.is_empty());
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
