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

    pub fn into_organizations(self, filter: Pattern) -> impl Iterator<Item = Organization> {
        self.organizations
            .into_iter()
            .filter(move |o| filter.matches(&o.name))
    }
}

fn organizations_from_dir(dir: &Path) -> impl Iterator<Item = Organization> {
    WalkDir::new(dir)
        .min_depth(1)
        .max_depth(1)
        .follow_links(true)
        .sort_by_file_name()
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::File;
    use std::io::Write;

    use serial_test::serial;
    use tempfile;
    use tempfile::TempDir;

    fn create_mock_toml(dir: &Path, name: &str) {
        let filepath = dir.join(format!("{}.toml", name));
        let mut file = File::create(filepath).unwrap();
        write!(file, "username = \"{}_user\"\n[profiles]", name).unwrap();
    }

    fn create_mock_config_dir() -> TempDir {
        let tempdir = tempfile::tempdir().unwrap();

        for organization_name in ["foo", "bar", "baz"] {
            create_mock_toml(tempdir.path(), organization_name);
        }

        let bad_filepath = tempdir.path().join("bad.txt");
        let mut bad_file = File::create(bad_filepath).unwrap();
        write!(bad_file, "Not an oktaws config").unwrap();

        let bad_dir = tempdir.path().join("bad");
        std::fs::create_dir(&bad_dir).unwrap();
        let bad_nested_filepath = bad_dir.join("nested.txt");
        let mut bad_nested_file = File::create(bad_nested_filepath).unwrap();
        write!(bad_nested_file, "Not an oktaws config").unwrap();

        tempdir
    }

    #[test]
    #[serial]
    fn finds_all_configs() {
        let tempdir = create_mock_config_dir();
        env::set_var("OKTAWS_HOME", tempdir.path());

        let config = Config::new().unwrap();
        assert_eq!(config.organizations.len(), 3);
    }

    #[test]
    #[serial]
    fn does_not_find_nested_config() {
        let tempdir = create_mock_config_dir();

        env::set_var("OKTAWS_HOME", &tempdir.path());

        let mock_dir = tempdir.path().join("mock");
        std::fs::create_dir(&mock_dir).unwrap();
        create_mock_toml(&mock_dir, "quz");

        let config = Config::new().unwrap();
        assert_eq!(config.organizations.len(), 3);
    }

    #[test]
    #[serial]
    fn filters_into_organizations() {
        let tempdir = create_mock_config_dir();
        env::set_var("OKTAWS_HOME", tempdir.path());

        let config = Config::new().unwrap();
        assert_eq!(
            config
                .into_organizations(Pattern::new("*").unwrap())
                .map(|org| org.name)
                .collect::<Vec<_>>(),
            vec!["bar", "baz", "foo"]
        );

        let config = Config::new().unwrap();
        assert_eq!(
            config
                .into_organizations(Pattern::new("ba*").unwrap())
                .map(|org| org.name)
                .collect::<Vec<_>>(),
            vec!["bar", "baz"]
        );
    }
}
