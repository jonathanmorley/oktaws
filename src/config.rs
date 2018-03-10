use failure::Error;
use serde_json;
use toml;

use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::fs::File;
use std::io::Read;
use std::iter::FromIterator;
use std::iter;

#[serde(default)]
#[derive(StructOpt, Debug, Deserialize, Default)]
pub struct Config {
    /// Profile to update
    pub profile: Option<String>,

    /// Forces new credentials
    #[structopt(short = "f", long = "force-new")]
    pub force_new: bool,

    /// Specify Okta username (will prompt if not provided)
    #[structopt(short = "u", long = "username")]
    pub username: Option<String>,

    /// Sets the level of verbosity
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbosity: u64,

    /// Profile information (in json object format)
    #[structopt(long = "profiles", parse(try_from_str = "serde_json::from_str"),
                default_value = "{}")]
    pub profiles: HashMap<String, Profile>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Profile {
    pub organization: String,
    pub app_id: String,
    pub role: String,
}

impl Config {
    pub fn from_file(file_path: &Path) -> Result<Self, Error> {
        let mut buffer = String::new();

        if file_path.exists() && file_path.is_file() {
            File::open(file_path)?.read_to_string(&mut buffer)?;
            Ok(toml::from_str(&buffer)?)
        } else {
            let old_config_path = env::home_dir().unwrap().join(".oktaws/config");
            if old_config_path.exists() && old_config_path.is_file() {
                warn!(
                    "Deprecated config file found at {:?}, please move this to {:?} and convert \
                     to TOML (add quotes and 'profiles.' prefix to object keys)",
                    old_config_path, file_path
                );
            }
            Ok(Config::default())
        }
    }

    pub fn merge(self, other: Self) -> Self {
        Self {
            profile: self.profile.or(other.profile),
            force_new: self.force_new || other.force_new,
            verbosity: self.verbosity + other.verbosity,
            username: self.username.or(other.username),
            profiles: HashMap::from_iter(
                self.profiles.into_iter().chain(other.profiles.into_iter()),
            ),
        }
    }

    pub fn into_profiles(mut self) -> Vec<(String, Profile)> {
        match self.profile {
            Some(profile_name) => match self.profiles.remove(&profile_name) {
                Some(profile) => iter::once((profile_name, profile)).collect(),
                None => {
                    error!(
                        "Could not find profile '{}' in {:?}",
                        profile_name,
                        self.profiles.keys()
                    );

                    iter::empty().collect()
                }
            },
            None => self.profiles.into_iter().collect(),
        }
    }
}
