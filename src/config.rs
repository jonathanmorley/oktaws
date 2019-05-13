use crate::okta;
use crate::profile::{Profile, ProfileId};
use failure;
use log::*;
use log_derive::logfn;
use serde::Deserialize;
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::env::var as env_var;
use std::fmt;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub organizations: HashMap<String, Organization>,
}

impl TryFrom<&Path> for Config {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let contents = fs::read_to_string(path).context(ConfigRead {
            path: path.to_path_buf(),
        })?;

        toml::from_str(&contents)
            .context(ConfigParse {
                path: path.to_path_buf(),
            })
            .map_err(Into::into)
    }
}

impl TryFrom<PathBuf> for Config {
    type Error = Error;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Config::try_from(path.as_path())
    }
}

impl Config {
    #[logfn(Trace, fmt = "{:?}")]
    pub fn new() -> Result<Self, Error> {
        config_path()?.try_into()
    }

    pub fn into_profiles(self) -> impl Iterator<Item = (ProfileId, Profile)> {
        self.organizations
            .into_iter()
            .flat_map(|(org_name, org)| org.into_profiles(org_name).unwrap())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Organization {
    pub username: String,
    pub url: String,
    #[serde(rename = "role")]
    default_role: Option<String>,
    #[serde(rename = "profiles")]
    profile_specs: HashMap<String, ProfileSpec>,
}

impl Organization {
    // Construct dynamic profiles based on available okta tiles
    fn into_org_profiles(
        self,
        org_name: String,
    ) -> Result<HashMap<ProfileId, Profile>, failure::Error> {
        let org_role = self.clone().default_role;
        let okta_org = okta::Organization::from(self).with_session()?;

        trace!("Getting org profiles for {}", org_name);

        let profiles = okta_org
            .into_aws_applications()?
            .map(Profile::from)
            .map(move |profile| Profile {
                role: profile.role.clone().or_else(|| org_role.clone()),
                ..profile
            })
            .map(|profile| {
                (
                    ProfileId {
                        org_name: org_name.clone(),
                        profile_name: profile.application.link.label().unwrap().to_owned(),
                    },
                    profile,
                )
            })
            .collect();

        Ok(profiles)
    }

    // Construct profiles based on profile specs in the config
    pub fn into_config_profiles(
        self,
        org_name: String,
    ) -> Result<HashMap<ProfileId, Profile>, failure::Error> {
        let org_role = self.clone().default_role;
        let okta_org = okta::Organization::from(self.clone()).with_session()?;

        self.clone()
            .profile_specs
            .into_iter()
            .map(move |(profile_name, profile_spec)| {
                let application_name = match &profile_spec {
                    ProfileSpec::Application(application) => application,
                    ProfileSpec::ApplicationRole { application, .. } => application,
                };

                let application = okta_org.clone().into_application(application_name)?;

                let role = match profile_spec {
                    ProfileSpec::Application(_) => org_role.clone(),
                    ProfileSpec::ApplicationRole { role, .. } => {
                        role.clone().or_else(|| org_role.clone())
                    }
                };

                let profile = (
                    ProfileId {
                        org_name: org_name.clone(),
                        profile_name,
                    },
                    Profile { role, application },
                );

                Ok(profile)
            })
            .collect()
    }

    // Combine org profiles and config profiles
    #[logfn(Trace)]
    pub fn into_profiles(
        self,
        org_name: String,
    ) -> Result<HashMap<ProfileId, Profile>, failure::Error> {
        let mut org_profiles = self.clone().into_org_profiles(org_name.clone())?;
        let config_profiles = self.clone().into_config_profiles(org_name.clone())?;

        org_profiles.extend(config_profiles.into_iter());
        Ok(org_profiles)
    }
}

impl From<Organization> for okta::Organization {
    fn from(org: Organization) -> Self {
        okta::Organization::new(org.url, org.username)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ProfileSpec {
    Application(String),
    ApplicationRole {
        application: String,
        role: Option<String>,
    },
}

/// Get the location of the first found default config directory
/// according to the following order:
///
/// 1. $XDG_CONFIG_HOME/oktaws
/// 2. $HOME/.config/oktaws
/// 3. $HOME/.oktaws
fn config_dirs() -> Vec<PathBuf> {
    let mut fallbacks = Vec::new();

    if let Ok(xdg_home) = env_var("XDG_CONFIG_HOME") {
        fallbacks.push(PathBuf::from(xdg_home).join("oktaws"));
    }

    if let Ok(home) = env_var("HOME") {
        let home = PathBuf::from(home);
        fallbacks.push(home.join(".config").join("oktaws"));
        fallbacks.push(home.join(".oktaws"));
    }

    fallbacks
}

/// Use OKTAWS_CONFIG if provided, otherwise try `get_oktaws_directories` in order.
/// If none found, create a new config under the first element of `get_oktaws_directories`
fn config_path() -> Result<PathBuf, Error> {
    let config_file_name = "oktaws.toml";

    if let Ok(oktaws_config) = env_var("OKTAWS_CONFIG") {
        let oktaws_config = PathBuf::from(oktaws_config);

        if !oktaws_config.exists() {
            return Err(Error::NonexistantExplicitConfig {
                path: oktaws_config,
            });
        }

        if oktaws_config.is_file() {
            return Ok(oktaws_config);
        } else {
            return Err(Error::NotConfigFile {
                path: oktaws_config,
            });
        }
    }

    let existing_config = config_dirs()
        .into_iter()
        .map(|dir| dir.join(config_file_name))
        .find(|config| config.exists());

    if let Some(existing_config) = existing_config {
        Ok(existing_config)
    } else if let Some(config_dir) = config_dirs().into_iter().next() {
        if !config_dir.exists() {
            info!("creating {:?} directory", &config_dir);
            fs::create_dir_all(&config_dir).context(CreateDir {
                path: config_dir.clone(),
            })?;
        }

        let config_file = config_dir.join(config_file_name);
        info!("creating {:?} file", &config_file);
        File::create(&config_file).context(CreateConfig {
            path: config_file.clone(),
        })?;

        Ok(config_file)
    } else {
        Err(Error::UnplaceableConfig)
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("config path provided from $OKTAWS_CONFIG ({}) not found", path.display()))]
    NonexistantExplicitConfig { path: PathBuf },
    #[snafu(display("config at {} is not a file", path.display()))]
    NotConfigFile { path: PathBuf },
    #[snafu(display("no config found, and no suitable location found to create a default"))]
    UnplaceableConfig,
    #[snafu(display("unable to read config from {}: {}", path.display(), source))]
    ConfigRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("unable to parse config from {}: {}", path.display(), source))]
    ConfigParse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[snafu(display("unable to create directory at {}: {}", path.display(), source))]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("unable to create config at {}: {}", path.display(), source))]
    CreateConfig {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use serial_test_derive::serial;
    use tempfile::{tempdir, NamedTempFile};

    #[test]
    #[serial]
    fn dirs_with_no_env_vars() {
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");

        let v: Vec<PathBuf> = vec![];
        assert_eq!(config_dirs(), v)
    }

    #[test]
    #[serial]
    fn dirs_with_home_var() {
        let home = tempdir().unwrap();

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_var("HOME", home.path());

        assert_eq!(
            config_dirs(),
            vec![
                home.path().join(".config/oktaws"),
                home.path().join(".oktaws")
            ]
        );
    }

    #[test]
    #[serial]
    fn dirs_with_xdg_config_home_var() {
        let home = tempdir().unwrap();
        let xdg_home = tempdir().unwrap();

        std::env::set_var("XDG_CONFIG_HOME", xdg_home.path());
        std::env::set_var("HOME", home.path());

        assert_eq!(
            config_dirs(),
            vec![
                xdg_home.path().join("oktaws"),
                home.path().join(".config/oktaws"),
                home.path().join(".oktaws")
            ]
        );
    }

    #[test]
    #[serial]
    fn config_with_oktaws_config_var() {
        let oktaws_config = NamedTempFile::new().unwrap();
        let home = tempdir().unwrap();
        let xdg_home = tempdir().unwrap();

        std::env::set_var("OKTAWS_CONFIG", oktaws_config.path());
        std::env::set_var("XDG_CONFIG_HOME", xdg_home.path());
        std::env::set_var("HOME", home.path());

        let config = config_path().unwrap();

        assert_eq!(config, oktaws_config.path());

        assert!(config.exists());
        assert!(config.is_file());
    }

    #[test]
    #[serial]
    fn config_with_non_existant_oktaws_config_var() {
        let home = tempdir().unwrap();
        let xdg_home = tempdir().unwrap();

        std::env::set_var("OKTAWS_CONFIG", "/non-existant-path");
        std::env::set_var("XDG_CONFIG_HOME", xdg_home.path());
        std::env::set_var("HOME", home.path());

        let err = config_path().unwrap_err();

        assert_eq!(
            err.to_string(),
            r#"config path provided from $OKTAWS_CONFIG (/non-existant-path) not found"#
        )
    }

    #[test]
    #[serial]
    fn config_with_no_files() {
        let home = tempdir().unwrap();
        let xdg_home = tempdir().unwrap();

        std::env::remove_var("OKTAWS_CONFIG");
        std::env::set_var("XDG_CONFIG_HOME", xdg_home.path());
        std::env::set_var("HOME", home.path());

        let config = config_path().unwrap();

        assert_eq!(config, xdg_home.path().join("oktaws/oktaws.toml"));

        assert!(config.exists());
        assert!(config.is_file());
    }

    #[test]
    #[serial]
    fn config_with_xdg_file() {
        let home = tempdir().unwrap();
        let xdg_home = tempdir().unwrap();

        std::env::remove_var("OKTAWS_CONFIG");
        std::env::set_var("XDG_CONFIG_HOME", xdg_home.path());
        std::env::set_var("HOME", home.path());

        fs::create_dir_all(&xdg_home.path().join("oktaws")).unwrap();
        File::create(&xdg_home.path().join("oktaws/oktaws.toml")).unwrap();

        let config = config_path().unwrap();

        assert_eq!(config, xdg_home.path().join("oktaws/oktaws.toml"));
    }

    #[test]
    #[serial]
    fn config_with_home_file() {
        let home = tempdir().unwrap();
        let xdg_home = tempdir().unwrap();

        std::env::remove_var("OKTAWS_CONFIG");
        std::env::set_var("XDG_CONFIG_HOME", xdg_home.path());
        std::env::set_var("HOME", home.path());

        fs::create_dir_all(&home.path().join(".oktaws")).unwrap();
        File::create(&home.path().join(".oktaws/oktaws.toml")).unwrap();

        let config = config_path().unwrap();

        assert_eq!(config, home.path().join(".oktaws/oktaws.toml"));
    }

    #[test]
    #[serial]
    fn config_with_no_env_vars() {
        std::env::remove_var("OKTAWS_CONFIG");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");

        let err = config_path().unwrap_err();

        assert_eq!(
            err.to_string(),
            "no config found, and no suitable location found to create a default"
        )
    }
}
