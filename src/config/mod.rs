pub mod credentials;
pub mod organization;

use crate::config::organization::Organization;

use std::{convert::TryInto, env::var as env_var};
use std::path::Path;
use std::path::PathBuf;

use dirs;
use failure::Error;
use walkdir::WalkDir;
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
        .filter_map(|e| match e.path().try_into() {
            Ok(organization) => Some(organization),
            Err(err) => {
                warn!("Could not parse {:?} as an Organization ({:?})", e.path(), err);
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
    
    use assert_cmd::prelude::*;
    use tempfile::tempdir;

    use std::process::Command;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_bad_organization_in_dir() {
        let tmp_dir = tempdir().unwrap();

        let file_path = tmp_dir.path().join("my-bad-org.toml");

        let mut tmp_file = File::create(file_path).unwrap();
        writeln!(tmp_file, "Not parseable as toml").unwrap();

        assert_eq!(organizations_from_dir(tmp_dir.path()).count(), 0);

        let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
        let assert = cmd
            .env("OKTAWS_HOME", tmp_dir.path())
            .assert();
        assert
            .failure()
            .code(1)
            .stderr(predicates::str::is_match(r#" WARN  oktaws::config > Could not parse ".+/my-bad-org.toml" as an Organization \(Error \{ inner: ErrorInner \{ kind: Wanted \{ expected: "an equals", found: "an identifier" \}, line: Some\(0\), col: 4, at: Some\(4\), message: "", key: \[\] \} \}\)\nError: ErrorMessage \{ msg: "No organizations found called \*" }\n"#).unwrap());
    }
}
